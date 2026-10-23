import json

from fabriclib.images.bundle.fetch_blob import fetch_blob
from fabriclib.images.bundle.fetch_image import INDEX_TYPES
from fabriclib.images.bundle.registry_name import registry_name


def image_size(repo, digest, arch):
    """Purpose: how many bytes one image of the lock takes for one architecture, from its manifests alone (nothing
             large is fetched), so an export can refuse before it starts when the space is not there.
    Inputs:  repo — str, the lock's repository; digest — the pinned "sha256:…"; arch — "amd64" | "arm64".
    Returns: int, the sum of its index, manifest, config and layer sizes; 0 when the index has no linux/<arch>
             image (fetch_image then refuses it, naming it).
    Fails:   ValidationError when the registry refuses or a manifest does not match its digest;
             urllib.error.URLError when the registry cannot be reached.
    Feeds:   export_bundle."""
    host, path, _ = registry_name(repo)
    top, size, toptype = fetch_blob(host, path, digest, manifest=True)
    parsed = json.loads(top)
    if (parsed.get("mediaType") or toptype) in INDEX_TYPES:
        found = [m for m in parsed.get("manifests") or [] if (m.get("platform") or {}).get("os") == "linux"
                 and (m.get("platform") or {}).get("architecture") == arch]
        if not found:
            return 0
        man, n, _ = fetch_blob(host, path, found[0]["digest"], manifest=True)
        size += n
        parsed = json.loads(man)
    return size + parsed["config"]["size"] + sum(layer["size"] for layer in parsed.get("layers") or [])
