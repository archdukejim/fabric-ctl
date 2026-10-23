import os
import subprocess
import tarfile

from fabriclib.common.errors import ValidationError
from fabriclib.common.read_published_lock import read_published_lock
from fabriclib.images.bundle.check_bundle import check_bundle
from fabriclib.images.bundle.free_bytes import free_bytes
from fabriclib.images.bundle.host_arch import host_arch
from fabriclib.images.bundle.verify_offline import verify_offline
from fabriclib.images.constants import VERIFIED
from fabriclib.images.remember_verified import remember_verified

STORE = "/var/lib/containerd"      # where the containerd image store keeps images
TRUSTED_ROOT = "sigstore-trusted-root.json"   # beside the lock, shipped in the package (manual 1.14.4.6)
# what loading takes beside the carried bytes: the compressed content kept, plus the layers unpacked (about 2x)
STORE_FACTOR = 3


def _containerd_store():
    """Purpose: whether Docker keeps images in the containerd image store, the one that keeps an image's index and so
             knows a loaded image by the digest the lock pins (the classic store forgets it, and an offline host
             would then try to pull).
    Inputs:  none (asks `docker info`).
    Returns: bool.
    Fails:   ValidationError when Docker does not answer.
    Feeds:   import_bundle."""
    res = subprocess.run(["docker", "info", "--format", "{{json .DriverStatus}}"], capture_output=True, text=True,
                         timeout=60)
    if res.returncode != 0:
        raise ValidationError(f"Docker does not answer ({(res.stderr or '').strip()[:200]})")
    return "io.containerd.snapshotter" in res.stdout


def _present(ref):
    """Purpose: whether Docker has an image under this pinned ref (by its digest).
    Inputs:  ref — "repo:tag@sha256:…".
    Returns: bool.
    Fails:   never (a missing image is False).
    Feeds:   import_bundle."""
    return subprocess.run(["docker", "image", "inspect", ref], capture_output=True, timeout=60).returncode == 0


def _load(tar, member, key):
    """Purpose: one carried image into Docker, streamed from the bundle (nothing is unpacked to disk first).
    Inputs:  tar — the bundle open for reading; member — its image file's TarInfo; key — the image's key.
    Returns: None.
    Fails:   ValidationError with Docker's reason when it refuses the image.
    Feeds:   import_bundle."""
    proc = subprocess.Popen(["docker", "load", "-q"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    src = tar.extractfile(member)
    try:
        for chunk in iter(lambda: src.read(1 << 20), b""):
            proc.stdin.write(chunk)
    except BrokenPipeError:
        pass
    finally:
        proc.stdin.close()
    out, err = proc.stdout.read(), proc.stderr.read()
    if proc.wait() != 0:
        why = (err or out).decode(errors='replace').strip()[:300]
        raise ValidationError(f"{key}: Docker refused the image ({why})")


def import_bundle(bundle, lock_dir, signature_check=True, cache=VERIFIED, store=STORE, log=print):
    """Purpose: `fabricctl images import` and `setup --offline <bundle>`: load an offline bundle's images on a host
             with no internet (decision 2.1.14.14, manual 1.14.4.4) once everything checks: the bundle as a whole
             (check_bundle: version, architecture, every image of this fabric's lock and its digests, every hash),
             room in Docker's image store, then every published image's signature offline (fabric's signer and issuer
             from this fabric's own lock, the trusted root it ships), cosign itself being the one image loaded before
             that check (its bytes already proven to be the lock's). Images already present are not loaded again;
             nothing is fetched. Verified digests are remembered, so setup's online check is not needed for them.
    Inputs:  bundle — str path; lock_dir — the folder of this fabric's images.lock.yaml and VERSION (the package's);
             signature_check — the host's image_signature_check (False: signatures not checked, said so, 2.1.14.10);
             cache — the verified-digests file; store — the folder whose free space is checked (containerd's);
             log — progress printer.
    Returns: dict {"loaded": [keys], "present": [keys already in Docker], "verified": [refs],
             "unchecked": [refs whose signature was not checked]}.
    Fails:   ValidationError, saying why, before any image is loaded unless noted: Docker on the classic image store;
             no trusted root beside the lock; every refusal of check_bundle; not enough free space (needed and free
             named); a signature that does not
             verify (after cosign alone was loaded); Docker refusing an image, or not knowing one by its pinned digest
             after the load. OSError.
    Feeds:   run_images_command (`fabricctl images import`), setup/import_offline_bundle (`setup --offline`);
             tests/images/bundle.py, tests/images/offline.sh."""
    if not _containerd_store():
        raise ValidationError("this host's Docker keeps images in its classic store, which forgets the digest an "
                              "image is pinned by once it is loaded, so the services would try to pull it: offline "
                              "bundles need the containerd image store (Docker 29's default on a new host; manual "
                              "1.14.4.5)")
    root_file = os.path.join(lock_dir, TRUSTED_ROOT)
    if signature_check and not os.path.exists(root_file):
        raise ValidationError(f"this fabric ships no Sigstore trusted root ({root_file}), so no signature can be "
                              "checked offline")
    checked = check_bundle(bundle, lock_dir, host_arch(), log=log)
    manifest, indexes = checked["manifest"], checked["indexes"]
    images = manifest["images"]
    keys = sorted(indexes)
    todo = [k for k in keys if not _present(images[k]["ref"])]
    need = STORE_FACTOR * sum(manifest["files"][images[k]["file"]]["size"] for k in todo)
    free = free_bytes(store)
    if free < need:
        raise ValidationError(f"not enough space for the images in {store}: about {need >> 20} MiB is needed, "
                              f"{free >> 20} MiB is free")
    published = [k for k in keys if images[k].get("signature")]
    lock = read_published_lock(lock_dir)
    out = {"loaded": [], "present": sorted(set(keys) - set(todo)), "verified": [], "unchecked": []}
    with tarfile.open(bundle, mode="r:") as tar:
        members = {m.name: m for m in tar.getmembers() if m.isfile()}
        if published and signature_check:
            if "cosign" in todo:
                log("loading cosign (to check the signatures)")
                _load(tar, members[images["cosign"]["file"]], "cosign")
                todo.remove("cosign")
                out["loaded"].append("cosign")
            with open(root_file, "rb") as f:
                root = f.read()
            for k in published:
                sig = tar.extractfile(members[images[k]["signature"]]).read()
                verify_offline(images[k]["ref"], indexes[k], sig, root, images["cosign"]["ref"],
                               lock["signer"], lock["issuer"])
                log(f"{k}: signature verified offline")
                out["verified"].append(images[k]["ref"])
        elif published:
            out["unchecked"] = [images[k]["ref"] for k in published]
            log("image_signature_check is false: the published images' signatures are not checked")
        for k in todo:
            log(f"loading {k}")
            _load(tar, members[images[k]["file"]], k)
            out["loaded"].append(k)
    unknown = [k for k in keys if not _present(images[k]["ref"])]
    if unknown:
        raise ValidationError("Docker does not know these images by their pinned digest after loading them: "
                              + ", ".join(unknown))
    if out["verified"]:
        remember_verified(cache, out["verified"])
    return out
