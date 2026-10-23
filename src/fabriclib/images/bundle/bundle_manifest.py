import json
import os
import tarfile

from fabriclib.common.errors import ValidationError
from fabriclib.images.bundle.export_bundle import FORMAT, MANIFEST


def bundle_manifest(tar, bundle, lock_dir, arch, release):
    """Purpose: an open offline bundle's manifest, once it is shown to be for this host (manual 1.14.4.3): readable,
             of this fabric's format, for this fabric's version, this host's architecture and its Ubuntu release.
    Inputs:  tar — the bundle, a tarfile open for reading; bundle — its path (for messages); lock_dir — the package's
             folder (VERSION); arch — this host's architecture; release — this host's Ubuntu release ("24.04").
    Returns: (manifest dict, {member name: TarInfo} of its files).
    Fails:   ValidationError, saying why: cut short or a broken header (damaged); no manifest, not JSON, another
             format; for another fabric version, architecture or Ubuntu release (each naming both and what to export).
    Feeds:   check_bundle, extract_bundle_apt."""
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
    carried = (manifest.get("ubuntu") or {}).get("release")
    if carried != release:
        raise ValidationError(f"this bundle's packages are for Ubuntu {carried}, this host runs {release}: "
                              f"export one with --ubuntu {release}")
    return manifest, members
