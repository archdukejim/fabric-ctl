import hashlib
import json
import os
import tarfile

from fabriclib.common.errors import ValidationError
from fabriclib.images.bundle.bundle_images import bundle_images
from fabriclib.images.bundle.export_bundle import FORMAT, MANIFEST
from fabriclib.images.bundle.fetch_image import INDEX_TYPES


def _hash(f):
    """Purpose: sha256 and length of a stream, read in 1 MiB pieces.
    Inputs:  f — a binary file object.
    Returns: (hex digest str, size int).
    Fails:   OSError, tarfile.ReadError or EOFError when the stream is cut short (a damaged bundle).
    Feeds:   check_bundle, _check_image."""
    h, n = hashlib.sha256(), 0
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
        n += len(chunk)
    return h.hexdigest(), n


def _check_image(key, entry, f, arch):
    """Purpose: one carried image proven to be the lock's, from its own bytes: the layout's index names the lock's
             digest, the image's index hashes to it, and the linux/<arch> manifest it lists, its config and every
             layer are present and hash to the digests that name them.
    Inputs:  key — the image's key (for messages); entry — bundle_images entry (repo, tag, digest); f — the image's
             tar, a seekable binary file object; arch — the host's architecture.
    Returns: bytes, the image's index (what fabric's published images' signatures sign).
    Fails:   ValidationError naming the image and what does not match.
    Feeds:   check_bundle."""
    with tarfile.open(fileobj=f, mode="r:") as tar:
        names = {os.path.normpath(m.name): m for m in tar.getmembers() if m.isfile()}

        def read(digest):
            m = names.get(f"blobs/sha256/{digest[7:]}")
            if m is None:
                raise ValidationError(f"{key}: its blob {digest[:19]}… is missing")
            data = tar.extractfile(m).read() if m.size < (4 << 20) else None
            got, _ = _hash(tar.extractfile(m))
            if f"sha256:{got}" != digest:
                raise ValidationError(f"{key}: its blob {digest[:19]}… does not match its digest (damaged or altered)")
            return data

        layout = json.loads(tar.extractfile(names["index.json"]).read()) if "index.json" in names else {}
        if [d.get("digest") for d in layout.get("manifests") or []] != [entry["digest"]]:
            raise ValidationError(f"{key}: the bundle's image is not the one the lock pins ({entry['digest'][:19]}…)")
        top = read(entry["digest"])
        parsed = json.loads(top)
        if (parsed.get("mediaType") or layout["manifests"][0].get("mediaType")) in INDEX_TYPES:
            found = [m["digest"] for m in parsed.get("manifests") or []
                     if (m.get("platform") or {}).get("os") == "linux"
                     and (m.get("platform") or {}).get("architecture") == arch]
            if not found:
                raise ValidationError(f"{key}: the image has no linux/{arch} manifest")
            manifest = json.loads(read(found[0]))
        else:
            manifest = parsed
        config = json.loads(read(manifest["config"]["digest"]))
        if config.get("architecture") != arch:
            raise ValidationError(f"{key}: the carried image is linux/{config.get('architecture')}, not linux/{arch}")
        for layer in manifest.get("layers") or []:
            read(layer["digest"])
        return top


def check_bundle(bundle, lock_dir, arch, log=print):
    """Purpose: everything about an offline bundle that can be proven without Docker, before anything is loaded
             (decision 2.1.14.14, manual 1.14.4.3): it is whole, it is for this fabric's version and this host's
             architecture, it carries every image this fabric's lock pins and each is exactly the pinned one, every
             file matches the manifest's sha256, and each published image carries its signature.
    Inputs:  bundle — str path of the bundle; lock_dir — the folder of this fabric's images.lock.yaml and VERSION
             (the package's: what setup deploys); arch — this host's architecture; log — progress printer.
    Returns: dict {"manifest": the bundle's manifest, "indexes": {key: the image's index bytes}}.
    Fails:   ValidationError, saying why: not a tar or cut short (damaged); no manifest or an unknown format; for
             another fabric version or architecture; an image of the lock missing, or not the pinned one; a file
             missing or not matching its hash; a published image without its signature.
    Feeds:   import_bundle; tests/images/bundle.py."""
    try:
        tar = tarfile.open(bundle, mode="r:")
    except (tarfile.ReadError, EOFError, OSError) as e:
        raise ValidationError(f"{bundle} is not a readable bundle (damaged or not a tar: {e})")
    with tar:
        try:
            members = {m.name: m for m in tar.getmembers() if m.isfile()}
        except (tarfile.ReadError, EOFError) as e:
            raise ValidationError(f"{bundle} is damaged: it ends early or a header is broken ({e})")
        if MANIFEST not in members:
            raise ValidationError(f"{bundle} has no {MANIFEST}: not a fabric offline bundle")
        try:
            manifest = json.loads(tar.extractfile(members[MANIFEST]).read())
        except ValueError as e:
            raise ValidationError(f"{bundle}: its {MANIFEST} is not JSON ({e})")
        if manifest.get("format") != FORMAT:
            raise ValidationError(f"{bundle}: bundle format {manifest.get('format')!r}, this fabric reads {FORMAT}")
        with open(os.path.join(lock_dir, "VERSION")) as f:
            version = f.read().strip()
        if manifest.get("fabric") != version:
            raise ValidationError(f"this bundle is for fabric {manifest.get('fabric')}, this host's is {version}: "
                                  f"export one from fabric {version}")
        if manifest.get("arch") != arch:
            raise ValidationError(f"this bundle is for {manifest.get('arch')}, this host is {arch}: "
                                  f"export one with --arch {arch}")
        files = manifest.get("files") or {}
        wanted = {k: e for k, e in bundle_images(lock_dir).items() if not e["pending"]}
        carried = manifest.get("images") or {}
        missing = sorted(set(wanted) - set(carried))
        if missing:
            raise ValidationError(f"the bundle lacks images this fabric's lock pins: {', '.join(missing)}")
        for key, e in wanted.items():
            if carried[key].get("digest") != e["digest"] or carried[key].get("file") != e["file"]:
                raise ValidationError(f"{key}: the bundle carries {carried[key].get('digest')}, the lock pins "
                                      f"{e['digest']}")
            if e["file"] not in files:
                raise ValidationError(f"{key}: its image file {e['file']} is not in the manifest's files")
            if e["published"] and carried[key].get("signature") not in files:
                raise ValidationError(f"{key}: the bundle carries no signature for fabric's published image")
        for name, want in sorted(files.items()):
            if name not in members:
                raise ValidationError(f"the bundle lacks {name}, which its manifest lists")
            log(f"checking {name}")
            try:
                got, size = _hash(tar.extractfile(members[name]))
            except (tarfile.ReadError, EOFError, OSError) as e:
                raise ValidationError(f"{name} in the bundle is damaged ({e})")
            if got != want.get("sha256") or size != want.get("size"):
                raise ValidationError(f"{name} does not match its hash in the manifest (damaged or altered)")
        indexes = {}
        for key, e in wanted.items():
            try:
                indexes[key] = _check_image(key, e, tar.extractfile(members[e["file"]]), arch)
            except (tarfile.ReadError, EOFError, KeyError, ValueError) as err:
                if isinstance(err, ValidationError):
                    raise
                raise ValidationError(f"{key}: its image file is not an image layout ({err})")
        return {"manifest": manifest, "indexes": indexes}
