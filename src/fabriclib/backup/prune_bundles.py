import os

from fabriclib.backup.list_bundles import list_bundles
from fabriclib.backup.make_bundle import FOLDER


def prune_bundles(keep, folder=FOLDER):
    """Purpose: keep the newest `keep` scheduled bundles and remove the older ones (manual 1.3.7.5). Bundles made by
             hand, at uninstall or at reinstall are never removed here.
    Inputs:  keep — int, at least 1; folder — the backups folder.
    Returns: [file names removed].
    Fails:   ValueError for keep below 1; OSError removing a file.
    Feeds:   run_backup_command (after a scheduled bundle is whole)."""
    if keep < 1:
        raise ValueError("backup_keep must be at least 1")
    scheduled = [b for b in list_bundles(folder) if b["kind"] == "scheduled"]
    removed = []
    for bundle in scheduled[keep:]:
        os.remove(bundle["path"])
        removed.append(bundle["file"])
    return removed
