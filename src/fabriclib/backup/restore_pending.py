"""What an online bundle's restore leaves for setup to load (manual 1.3.7.6): config/restore-pending.json, crossed off
as each dump is loaded, so a setup run again goes on where it stopped."""
import json
import os


def read_restore_pending(config_dir):
    """Purpose: the dumps still to load after a restore.
    Inputs:  config_dir — fabric's config folder.
    Returns: {section: dump path} (empty when nothing is pending, or no restore ran).
    Fails:   ValueError on a file that is not JSON (a hand edit).
    Feeds:   load_directory_dump, load_vault_snapshot, load_signin_dump (through setup's steps)."""
    path = os.path.join(config_dir, "restore-pending.json")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def write_restore_pending(config_dir, pending):
    """Purpose: the dumps still to load, written atomically (0600); the file is removed once none is left.
    Inputs:  config_dir — fabric's config folder; pending — {section: dump path}.
    Returns: None.
    Fails:   OSError.
    Feeds:   restore_bundle, and each loader as it crosses its dump off."""
    path = os.path.join(config_dir, "restore-pending.json")
    if not pending:
        if os.path.exists(path):
            os.remove(path)
        return
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(pending, f, indent=2)
    os.replace(path + ".tmp", path)
