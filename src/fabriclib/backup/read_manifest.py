import json
import tarfile

from fabriclib.common.errors import ValidationError

FORMATS = (1,)


def read_manifest(path):
    """Purpose: a bundle's manifest (manual 1.3.7.2), read without any key.
    Inputs:  path — a bundle file.
    Returns: the manifest, dict, with "members": {name: size} of the bundle's tar added.
    Fails:   ValidationError when the file is not a tar, has no manifest.json, the manifest is not JSON or is of an
             unknown format; OSError when the file cannot be read.
    Feeds:   check_bundle, list_bundles, the console's and setup site's bundle views."""
    try:
        with tarfile.open(path, mode="r:") as tar:
            members = {m.name: m.size for m in tar.getmembers() if m.isfile()}
            if "manifest.json" not in members:
                raise ValidationError(f"{path} is not a fabric bundle: it has no manifest.json")
            manifest = json.loads(tar.extractfile("manifest.json").read())
    except (tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{path} is not a fabric bundle: {exc}") from None
    if not isinstance(manifest, dict) or manifest.get("format") not in FORMATS:
        found = manifest.get("format") if isinstance(manifest, dict) else "?"
        raise ValidationError(f"{path}: unknown bundle format {found}")
    manifest["members"] = members
    return manifest
