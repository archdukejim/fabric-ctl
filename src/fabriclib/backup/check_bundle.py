import hashlib
import tarfile

from fabriclib.backup.read_manifest import read_manifest
from fabriclib.backup.sections import ORDER
from fabriclib.common.errors import ValidationError


def check_bundle(path):
    """Purpose: whether a bundle is whole (manual 1.3.7.2, 1.3.7.12), before any key is asked: its manifest, key.age,
             every one of the seven sections, and each section's SHA-256 against the manifest.
    Inputs:  path — a bundle file.
    Returns: the manifest (read_manifest), checked.
    Fails:   ValidationError naming the first problem: a section missing, unknown or listed twice, a size or SHA-256
             that differs (the file was changed or cut short), no key.age; from read_manifest.
    Feeds:   restore_bundle, restore_section, `fabricctl backup check`, list_bundles."""
    manifest = read_manifest(path)
    entries = manifest.get("sections") or []
    names = [e.get("name") for e in entries]
    if sorted(names) != sorted(ORDER):
        raise ValidationError(f"{path}: the sections are {', '.join(map(str, names)) or 'none'}, "
                              f"not the seven of a bundle ({', '.join(ORDER)})")
    if "key.age" not in manifest["members"]:
        raise ValidationError(f"{path}: no key.age: the bundle cannot be opened")
    with tarfile.open(path, mode="r:") as tar:
        for entry in entries:
            member = entry.get("file")
            if manifest["members"].get(member) != entry.get("size"):
                raise ValidationError(f"{path}: section {entry['name']} is missing or not its recorded size")
            digest = hashlib.sha256()
            src = tar.extractfile(member)
            for chunk in iter(lambda: src.read(1 << 20), b""):
                digest.update(chunk)
            if digest.hexdigest() != entry.get("sha256"):
                raise ValidationError(f"{path}: section {entry['name']} has changed since the bundle was made "
                                      "(its SHA-256 differs): nothing is restored from it")
    return manifest
