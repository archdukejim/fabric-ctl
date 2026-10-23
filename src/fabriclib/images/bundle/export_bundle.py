import hashlib
import io
import json
import os
import tarfile
import time

from fabriclib.common.errors import ValidationError
from fabriclib.common.read_published_lock import read_published_lock
from fabriclib.images.bundle.bundle_images import bundle_images
from fabriclib.images.bundle.fetch_image import fetch_image
from fabriclib.images.bundle.fetch_signature import fetch_signature
from fabriclib.images.bundle.free_bytes import free_bytes
from fabriclib.images.bundle.image_size import image_size

ARCHES = ("amd64", "arm64")
FORMAT = 1
MANIFEST = "manifest.json"
TRUSTED_ROOT = "sigstore-trusted-root.json"     # shipped in the package beside the lock (manual 1.14.4.6)
SLACK = 64 << 20                                   # the manifest, signatures and tar headers, generously


def _sha256(path):
    """Purpose: a file's sha256, read in 1 MiB pieces.
    Inputs:  path — str.
    Returns: str hex digest.
    Fails:   OSError.
    Feeds:   export_bundle."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _add(tar, name, data, files):
    """Purpose: one in-memory file into the bundle, its hash and size recorded for the manifest.
    Inputs:  tar — the bundle open for writing; name — member path; data — bytes; files — the manifest's files dict.
    Returns: None.
    Fails:   OSError on write.
    Feeds:   export_bundle."""
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(data), 0o644, int(time.time())
    tar.addfile(info, io.BytesIO(data))
    files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def export_bundle(lock_dir, arch, out, log=print):
    """Purpose: `fabricctl images export`: one offline install bundle for this fabric release and one architecture
             (decision 2.1.14.14, manual 1.14.4): every image of the lock by its pinned digest, fabric's published
             images' signature bundles to check them with offline (against the trusted root the package ships), and
             a manifest of versions, digests and every file's sha256. Written beside `out` as `<out>.part` and
             renamed when whole.
    Inputs:  lock_dir — str, the folder holding images.lock.yaml and VERSION; arch — "amd64" | "arm64";
             out — str, the bundle file to write (its folder must exist; the file must not); log — progress printer.
    Returns: dict, the manifest written.
    Fails:   ValidationError, nothing written: an unknown architecture; `out` exists or its folder does not; an image
             of the lock not published (pending, with why) or with no linux/<arch> image; not enough free space
             beside `out` (needed and free named); a registry or Sigstore refusing or a blob not matching its digest
             (the partial file is removed). urllib.error.URLError when a registry cannot be reached; OSError.
    Feeds:   run_images_command (`fabricctl images export`); tests/images/bundle.py."""
    if arch not in ARCHES:
        raise ValidationError(f"unknown architecture {arch!r}: amd64 or arm64")
    folder = os.path.dirname(os.path.abspath(out))
    if not os.path.isdir(folder):
        raise ValidationError(f"{folder} does not exist")
    if os.path.exists(out):
        raise ValidationError(f"{out} exists: remove it or name another file")
    with open(os.path.join(lock_dir, "VERSION")) as f:
        version = f.read().strip()
    images = bundle_images(lock_dir)
    pending = [f"{k} ({e['pending']})" for k, e in images.items() if e["pending"]]
    if pending:
        raise ValidationError("a bundle carries every image of the lock, and these are not published: "
                              + "; ".join(pending) + ". Export from a release whose images are all published")
    sizes = {k: image_size(e["repo"], e["digest"], arch) for k, e in images.items()}
    missing = [k for k, n in sizes.items() if not n]
    if missing:
        raise ValidationError(f"no linux/{arch} image in the lock for: {', '.join(missing)}")
    need, free = sum(sizes.values()) + max(sizes.values()) + SLACK, free_bytes(folder)
    if free < need:
        raise ValidationError(f"not enough space in {folder}: the bundle needs about {need >> 20} MiB "
                              f"(with room for one image while it is added), {free >> 20} MiB is free")
    published = read_published_lock(lock_dir)
    cosign = images["cosign"]["ref"]
    part = out + ".part"
    manifest = {"format": FORMAT, "fabric": version, "arch": arch,
                "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "signer": published.get("signer", ""), "issuer": published.get("issuer", ""),
                "images": {}, "files": {}}
    try:
        with tarfile.open(part, "w", format=tarfile.PAX_FORMAT) as tar:
            for key, e in images.items():
                log(f"{key}: {e['ref']} ({sizes[key] >> 20} MiB)")
                tmp = f"{part}.{key.replace('/', '-')}.tar"
                got = fetch_image(e["repo"], e["tag"], e["digest"], arch, tmp)
                try:
                    manifest["files"][e["file"]] = {"sha256": _sha256(tmp), "size": os.path.getsize(tmp)}
                    tar.add(tmp, arcname=e["file"])
                finally:
                    os.remove(tmp)
                entry = {"ref": e["ref"], "name": got["name"], "digest": e["digest"], "manifest": got["manifest"],
                         "file": e["file"], "signature": None}
                if e["published"]:
                    entry["signature"] = f"signatures/{key.replace('/', '-')}.json"
                    _add(tar, entry["signature"], fetch_signature(e["ref"], cosign), manifest["files"])
                manifest["images"][key] = entry
            _add(tar, MANIFEST, json.dumps(manifest, indent=2, sort_keys=True).encode(), {})
        os.rename(part, out)
    except BaseException:
        for p in [part] + [os.path.join(folder, n) for n in os.listdir(folder)
                           if n.startswith(os.path.basename(part) + ".")]:
            if os.path.exists(p):
                os.remove(p)
        raise
    return manifest
