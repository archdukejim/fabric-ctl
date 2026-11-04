"""The sizing advice's state, on the host (manual 1.8.8.8): the timer's last result and each person's dismissals, beside
fabric's settings; nothing is sent anywhere. Page requests only ever read these files (1.8.8.2)."""
import json
import os
import tempfile

from fabriclib.common.errors import ValidationError
from fabriclib.sizing.advice import visible_alerts

RESULT, DISMISSED = "sizing.json", "sizing-dismissed.json"


def _load(path, default):
    """Purpose: one state file, or what stands for it when it is not there yet.
    Inputs:  path — str; default — returned for a file not there or not readable JSON.
    Returns: the JSON value, or default.
    Fails:   never.
    Feeds:   read_sizing, dismiss_alert."""
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_state(path, value):
    """Purpose: write a state file atomically, readable by root alone.
    Inputs:  path — str; value — JSON-serialisable.
    Returns: None.
    Fails:   OSError.
    Feeds:   refresh_sizing, dismiss_alert."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".sizing-")
    with os.fdopen(fd, "w") as f:
        json.dump(value, f)
    os.replace(tmp, path)


def read_sizing(config_dir, user=None):
    """Purpose: the last result, and one person's alerts in it (2.1.8.39: a dismissal is the person's own).
    Inputs:  config_dir — fabric's config directory; user — the person (None: every alert, the host's commands).
    Returns: {"at" (ISO, "" before the first run), "size", "alerts", "critical": bool, any critical among the alerts}.
    Fails:   never.
    Feeds:   agent route GET /v1/sizing, show_sizing."""
    last = _load(os.path.join(config_dir, RESULT), {})
    alerts = last.get("alerts") or []
    if user is not None:
        marks = _load(os.path.join(config_dir, DISMISSED), {}).get(user, {})
        alerts = visible_alerts(alerts, marks, last.get("size") or {})
    return {"at": last.get("at", ""), "size": last.get("size") or {}, "alerts": alerts,
            "critical": any(a["level"] == "critical" for a in alerts)}


def dismiss_alert(config_dir, user, resource):
    """Purpose: one person dismisses one alert until there is something new to say (2.1.8.39).
    Inputs:  config_dir — fabric's config directory; user — the person; resource — the alert's resource.
    Returns: {"resource", "level", "objects"} as recorded.
    Fails:   ValidationError when there is no such alert now; OSError writing.
    Feeds:   agent/post_sizing."""
    last = _load(os.path.join(config_dir, RESULT), {})
    alert = next((a for a in last.get("alerts") or [] if a["resource"] == resource), None)
    if alert is None:
        raise ValidationError(f"no sizing alert for {resource!r} now")
    size = last.get("size") or {}
    objects = sum(int(size.get(k) or 0) for k in ("people", "computers", "groups"))
    path = os.path.join(config_dir, DISMISSED)
    marks = _load(path, {})
    marks.setdefault(user, {})[resource] = {"level": alert["level"], "objects": objects}
    save_state(path, marks)
    return {"resource": resource, "level": alert["level"], "objects": objects}
