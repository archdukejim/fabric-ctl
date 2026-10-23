import hashlib
import os
import tarfile

from fabriclib.common.errors import ValidationError
from fabriclib.images.bundle.bundle_manifest import bundle_manifest
from fabriclib.images.bundle.host_arch import host_arch
from fabriclib.images.bundle.ubuntu_release import ubuntu_release

KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"


def extract_bundle_apt(bundle, lock_dir, dest):
    """Purpose: an offline bundle's packages made into a local, file-based apt source on this host (decision
             2.1.14.16, manual 1.14.4.10): its part of the Ubuntu archive and fabric's .deb unpacked into `dest`, each
             file checked against the manifest's hash, and an apt configuration that uses only that source —
             apt itself then checks Ubuntu's signatures (InRelease against the host's Ubuntu archive keyring) and
             every package's hash; nothing is added to the host's apt sources.
    Inputs:  bundle — str path; lock_dir — the package's folder (VERSION); dest — an empty folder (root's).
    Returns: dict {"config": path of the apt configuration, given to apt as APT_CONFIG (read before the host's
             /etc/apt/apt.conf.d, which it replaces, so no host hook asks for indexes the source lacks), "deb": path
             of fabric's .deb}.
    Fails:   ValidationError: everything bundle_manifest refuses (version, architecture, Ubuntu release, damage); a
             file that does not match its hash; a bundle with no packages; the Ubuntu archive keyring missing.
             OSError.
    Feeds:   setup/common/install_from_bundle."""
    if not os.path.exists(KEYRING):
        raise ValidationError(f"{KEYRING} is missing: apt could not check the bundle's Ubuntu packages")
    try:
        tar = tarfile.open(bundle, mode="r:")
    except (tarfile.ReadError, EOFError, OSError) as e:
        raise ValidationError(f"{bundle} is not a readable bundle (damaged or not a tar: {e})")
    with tar:
        manifest, members = bundle_manifest(tar, bundle, lock_dir, host_arch(), ubuntu_release()[0])
        ubuntu, deb = manifest.get("ubuntu") or {}, (manifest.get("deb") or {}).get("file")
        names = [n for n in manifest.get("files") or {} if n.startswith("ubuntu/") or n == deb]
        if not ubuntu.get("suites") or not deb:
            raise ValidationError(f"{bundle} carries no packages")
        for name in names:
            want = manifest["files"][name]
            path = os.path.join(dest, os.path.normpath(name))
            if not path.startswith(os.path.join(dest, "")) or name not in members:
                raise ValidationError(f"the bundle lacks {name}, or names a path outside it")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            h, src = hashlib.sha256(), tar.extractfile(members[name])
            with open(path, "wb") as f:
                for chunk in iter(lambda: src.read(1 << 20), b""):
                    h.update(chunk)
                    f.write(chunk)
            if h.hexdigest() != want["sha256"]:
                raise ValidationError(f"{name} does not match its hash in the manifest (damaged or altered)")
    apt = os.path.join(dest, "apt")
    for sub in ("lists/partial", "cache/archives/partial", "parts", "sources.d"):
        os.makedirs(os.path.join(apt, sub), exist_ok=True)
    with open(os.path.join(apt, "bundle.list"), "w") as f:
        for suite in ubuntu["suites"]:
            f.write(f"deb [signed-by={KEYRING}] file:{os.path.join(dest, 'ubuntu')} {suite} "
                    f"{' '.join(ubuntu['components'])}\n")
    config = os.path.join(apt, "apt.conf")
    with open(config, "w") as f:
        f.write(f'Dir::Etc::SourceList "{apt}/bundle.list";\nDir::Etc::SourceParts "{apt}/sources.d";\n'
                f'Dir::Etc::Parts "{apt}/parts";\nDir::State::Lists "{apt}/lists";\nDir::Cache "{apt}/cache";\n'
                'Acquire::By-Hash "no";\nAcquire::Languages "none";\n')
    return {"config": config, "deb": os.path.join(dest, deb)}
