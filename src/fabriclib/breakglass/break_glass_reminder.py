import json
import os

from fabriclib.breakglass.constants import RECORD
from fabriclib.common.write_audit import write_audit


def break_glass_reminder(config_dir, audit=write_audit):
    """Purpose: whether the break-glass password's file is still on the host (2.1.6.69): while it is, every
             administrator is told to copy it into safekeeping and delete it (the console, `fabricctl doctor`). Once
             it is gone, its removal is audited once (BREAK_GLASS_FILE_REMOVED) and the record dropped.
    Inputs:  config_dir — the install's config folder (<config>/break-glass.json, written by write_break_glass_file);
             audit — write_audit (tests give their own).
    Returns: {"path", "text"} while the file is there; None when there is no record or the file is gone.
    Fails:   OSError other than a missing record when the record cannot be read or removed, or the audit written.
    Feeds:   system/host_reminders (the console, through fabric-agent), setup/verify_install (doctor)."""
    record = os.path.join(config_dir, RECORD)
    try:
        with open(record) as f:
            data = json.load(f)
    except FileNotFoundError:
        return None
    except ValueError:
        data = {}
    path = str(data.get("path") or "")
    if path and os.path.exists(path):
        return {"path": path,
                "text": f"the break-glass password of fabric-admin is still in {path}: copy it into your own "
                        "safekeeping, then delete the file (2.1.6.69)"}
    audit("root", "BREAK_GLASS_FILE_REMOVED", f"file={path or 'unknown'}", "host")
    os.remove(record)
    return None
