import datetime
import json
import os

from fabriclib.common.paths import VARS_FILE
from fabriclib.common.write_audit import write_audit
from fabriclib.settings.constants import STATE_FILE


def mark_wizard_finished(how, actor, source="web", config_dir=None):
    """Purpose: record that the setup wizard has been applied once or dismissed (manual 1.8.5.3), so the first admin's
             sign-in no longer opens it and the Overview no longer shows *Finish setting up*. A dismissal is audited
             (SETTINGS_DISMISS); an apply is audited by apply_settings. The first record stays: an apply after a
             dismissal does not overwrite it.
    Inputs:  how — "applied" or "dismissed"; actor — who (audit); source — "web" or "cli"; config_dir — fabric's
             config folder (None: vars.yaml's).
    Returns: {"how", "by", "at"} as recorded (the earlier record when there is one).
    Fails:   ValueError for another how; OSError if the record or the audit log cannot be written.
    Feeds:   settings/apply_settings (applied), agent/post_settings (POST /v1/settings/dismiss)."""
    if how not in ("applied", "dismissed"):
        raise ValueError(how)
    path = os.path.join(config_dir or os.path.dirname(VARS_FILE), STATE_FILE)
    try:
        with open(path) as f:
            rec = json.load(f)
        if isinstance(rec, dict) and rec.get("how") in ("applied", "dismissed"):
            return {k: rec.get(k, "") for k in ("how", "by", "at")}
    except (OSError, ValueError):
        pass
    rec = {"how": how, "by": actor, "at": datetime.datetime.now().isoformat(timespec="seconds")}
    with open(path, "w") as f:
        json.dump(rec, f)
    if how == "dismissed":
        write_audit(actor, "SETTINGS_DISMISS", "the setup wizard dismissed", source)
    return rec
