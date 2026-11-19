import os

from fabriclib.backup.bundle_name import PATTERN
from fabriclib.backup.make_bundle import FOLDER
from fabriclib.backup.read_manifest import read_manifest
from fabriclib.common.errors import ValidationError


def list_bundles(folder=FOLDER):
    """Purpose: the bundles in the backups folder (manual 1.3.7.9), newest first, each described from its file name
             and manifest; reading a manifest needs no key.
    Inputs:  folder — the backups folder.
    Returns: [{"file", "path", "kind", "when", "size", "fabric_version", "host", "sections", "error"}]: "error" is the
             reason a file could not be read as a bundle, else None. Files that are not named as bundles are left out.
    Fails:   never for a missing folder ([]).
    Feeds:   run_backup_command (`backup list`), prune_bundles, the agent's backup routes."""
    try:
        names = os.listdir(folder)
    except FileNotFoundError:
        return []
    out = []
    for name in names:
        m = PATTERN.match(name)
        if not m:
            continue
        path = os.path.join(folder, name)
        row = {"file": name, "path": path, "kind": m["kind"], "when": m["when"], "size": os.path.getsize(path),
               "fabric_version": None, "host": m["host"], "sections": [], "error": None}
        try:
            manifest = read_manifest(path)
            row.update(fabric_version=manifest.get("fabric_version"),
                       sections=[s["name"] for s in manifest.get("sections", []) if not s.get("empty")])
        except (ValidationError, OSError) as exc:
            row["error"] = str(exc)
        out.append(row)
    return sorted(out, key=lambda r: r["when"], reverse=True)
