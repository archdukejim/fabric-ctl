import os
import shutil
import tempfile

from fabriclib.common.errors import ValidationError
from fabriclib.common.lock_dir import lock_dir
from fabriclib.images.bundle.extract_bundle_apt import extract_bundle_apt
from fabriclib.setup.common.apt_install import apt_install
from fabriclib.setup.errors import SetupError


def install_from_bundle(ctx, pkgs, hint):
    """Purpose: install packages on an offline host from its bundle (`setup --offline <bundle>`, decision 2.1.14.16):
             the bundle's packages as a local apt source used only for this install, removed afterwards; apt
             checks Ubuntu's signatures and hashes. The host's own apt sources are not changed.
    Inputs:  ctx — SetupContext: bundle (the path), source_dir (the package's folder); pkgs — package names;
             hint — what to check when apt fails.
    Returns: None; the packages installed.
    Fails:   SetupError with extract_bundle_apt's reason (a bundle for another release, damaged, no packages) or
             apt's (apt_install); OSError.
    Feeds:   setup/condition_host, setup/join_host_domain."""
    dest = tempfile.mkdtemp(prefix="fabric-offline-apt-", dir="/var/tmp")
    try:
        os.chmod(dest, 0o755)                     # apt's own user reads the files it checks
        try:
            source = extract_bundle_apt(ctx.bundle, lock_dir(os.path.join(ctx.source_dir, "jinja")), dest)
        except ValidationError as e:
            raise SetupError(f"offline bundle refused: {e}")
        apt_install(pkgs, hint, config=source["config"])
    finally:
        shutil.rmtree(dest, ignore_errors=True)
