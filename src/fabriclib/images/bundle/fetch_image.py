import io
import json
import os
import tarfile

from fabriclib.common.errors import ValidationError
from fabriclib.images.bundle.fetch_blob import fetch_blob
from fabriclib.images.bundle.registry_name import registry_name

INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")


def _add_bytes(tar, name, data):
    """Purpose: one file in the layout from bytes in memory.
    Inputs:  tar — tarfile open for writing; name — str member path; data — bytes.
    Returns: None.
    Fails:   OSError on write.
    Feeds:   fetch_image."""
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(data), 0o644, 0
    tar.addfile(info, io.BytesIO(data))


def _platform(index, arch, ref):
    """Purpose: the platform manifest of `arch` in a multi-arch index (attestation entries skipped).
    Inputs:  index — dict, the parsed index; arch — "amd64" | "arm64"; ref — str, for the message.
    Returns: dict, the index's descriptor for linux/<arch>.
    Fails:   ValidationError when the index has no linux/<arch> image.
    Feeds:   fetch_image."""
    for m in index.get("manifests") or []:
        p = m.get("platform") or {}
        if p.get("os") == "linux" and p.get("architecture") == arch and p.get("variant") in (None, "", "v8"):
            return m
    raise ValidationError(f"{ref}: has no linux/{arch} image")


def fetch_image(repo, tag, digest, arch, dest):
    """Purpose: one image of the lock for one architecture, by its pinned digest, as an OCI image layout in a tar
             file that `docker load` reads (decision 2.1.14.14, manual 1.14.4): the image's own index (whose digest
             is the lock's), the platform manifest, its config and layers — every one checked against its digest as
             it is fetched, so the bundle holds exactly what the lock pins and the host can check it again offline.
             The index's other platforms are named in it but not carried.
    Inputs:  repo, tag, digest — the lock's entry ("nginx", "1.30.5", "sha256:…"); arch — "amd64" | "arm64";
             dest — str path of the tar to write (its folder holds each layer briefly while it is added).
    Returns: dict {"name": the image's full name with its tag (docker.io/library/nginx:1.30.5), "digest",
             "manifest": the platform manifest's digest, "size": bytes of the blobs}.
    Fails:   ValidationError when the registry refuses, a blob does not match its digest or the image has no
             linux/<arch> platform (dest is removed then); urllib.error.URLError when the registry cannot be reached;
             OSError on write.
    Feeds:   export_bundle."""
    host, path, canonical = registry_name(repo)
    ref = f"{repo}:{tag}@{digest}"
    top, _, toptype = fetch_blob(host, path, digest, manifest=True)
    parsed = json.loads(top)
    toptype = parsed.get("mediaType") or toptype
    blobs = [(digest, top)]
    if toptype in INDEX_TYPES:
        desc = _platform(parsed, arch, ref)
        man, _, _ = fetch_blob(host, path, desc["digest"], manifest=True)
        blobs.append((desc["digest"], man))
        mdigest, manifest = desc["digest"], json.loads(man)
    else:
        mdigest, manifest = digest, parsed
    cdigest = manifest["config"]["digest"]
    config, _, _ = fetch_blob(host, path, cdigest)
    if (json.loads(config).get("architecture")) != arch:
        raise ValidationError(f"{ref}: is not a linux/{arch} image")
    blobs.append((cdigest, config))
    size = sum(len(b) for _, b in blobs)
    part = dest + ".layer"
    try:
        with tarfile.open(dest, "w", format=tarfile.PAX_FORMAT) as tar:
            _add_bytes(tar, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
            index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                     "manifests": [{"mediaType": toptype, "digest": digest, "size": len(top),
                                    "annotations": {"io.containerd.image.name": f"{canonical}:{tag}",
                                                    "org.opencontainers.image.ref.name": tag}}]}
            _add_bytes(tar, "index.json", json.dumps(index).encode())
            for d, data in blobs:
                _add_bytes(tar, f"blobs/sha256/{d[7:]}", data)
            for layer in manifest.get("layers") or []:
                with open(part, "wb") as f:
                    _, n, _ = fetch_blob(host, path, layer["digest"], sink=f)
                tar.add(part, arcname=f"blobs/sha256/{layer['digest'][7:]}")
                size += n
    except BaseException:
        for p in (dest, part):
            if os.path.exists(p):
                os.remove(p)
        raise
    finally:
        if os.path.exists(part):
            os.remove(part)
    return {"name": f"{canonical}:{tag}", "digest": digest, "manifest": mdigest, "size": size}
