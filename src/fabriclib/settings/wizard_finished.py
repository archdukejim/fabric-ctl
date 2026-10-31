import json
import os

from fabriclib.common.paths import VARS_FILE
from fabriclib.settings.constants import STATE_FILE


def wizard_finished(config_dir=None):
    """Purpose: whether the setup wizard has been applied once or dismissed (manual 1.8.5.3): until then the first
             admin's sign-in opens it and the Overview shows *Finish setting up*.
    Inputs:  config_dir — fabric's config folder (None: vars.yaml's), holding STATE_FILE.
    Returns: {"finished": bool, "how": "applied"|"dismissed"|"", "by", "at"}.
    Fails:   never (an unreadable record counts as not finished).
    Feeds:   settings/settings_overview (GET /v1/settings)."""
    path = os.path.join(config_dir or os.path.dirname(VARS_FILE), STATE_FILE)
    try:
        with open(path) as f:
            rec = json.load(f)
    except (OSError, ValueError):
        rec = {}
    rec = rec if isinstance(rec, dict) else {}
    how = rec.get("how") if rec.get("how") in ("applied", "dismissed") else ""
    return {"finished": bool(how), "how": how, "by": str(rec.get("by") or ""), "at": str(rec.get("at") or "")}
