import os
import subprocess

from fabriclib.common.console import ok
from fabriclib.setup.backup_install import ROOT_DIR
from fabriclib.setup.detach.constants import RECORD


def restore_install(ctx, src):
    """Purpose: put a backup_install() copy, or a full export_install() export, back under the install root,
             preserving owners and modes, before setup runs (setup then reuses the CA, secrets and certificates).
    Inputs:  ctx — SetupContext (deploy_base); src — the backup or export folder.
    Returns: None; each entry copied into deploy_base with cp -a, @root/ copied onto /, README.txt skipped; a setup
             run record copied with the config removed, so the setup that follows starts over (1.3.2.3.3).
    Fails:   CalledProcessError from cp -a; OSError listing src.
    Feeds:   cli main (`reinstall`), run_restore_command."""
    os.makedirs(ctx.deploy_base, exist_ok=True)
    for entry in os.listdir(src):
        if entry == "README.txt":         # an export's description of itself
            continue
        if entry == ROOT_DIR:           # absolute paths (the OpenBao seal key directory)
            subprocess.run(["cp", "-a", os.path.join(src, entry) + "/.", "/"], check=True)
            continue
        subprocess.run(["cp", "-a", os.path.join(src, entry), ctx.deploy_base + os.sep], check=True)
    record = os.path.join(ctx.config_dir, RECORD)
    if os.path.exists(record):            # a copied run record: the setup that follows starts over (2.1.2.26)
        os.remove(record)
    ok(f"restored config, CA and certificates from {src}")
