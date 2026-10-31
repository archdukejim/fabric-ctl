import datetime

import yaml

from fabriclib.settings.constants import FORMAT
from fabriclib.settings.read_settings import read_settings


def export_settings(v, version, now=None, have_gb=None):
    """Purpose: the settings file (manual 1.8.5.4): every wizard key's current value and nothing else — no
             console-only setting, no secret — under `fabric_settings: 1`, with when and where it was exported.
    Inputs:  v — the settings as saved (vars.yaml: site_name, hostname, the wizard's keys); version — this install's
             version (str); now — datetime (None: now, UTC); have_gb — the host's memory in GB (None: measured).
    Returns: {"text": the YAML, "name": "<site>-settings.yaml"}.
    Fails:   yaml.representer.RepresenterError for a value YAML cannot write (never for vars.yaml's own values).
    Feeds:   agent/get_route (GET /v1/settings/export), settings/run_settings_command (`fabricctl settings export`)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    site = str(v.get("site_name") or v.get("hostname") or "fabric")
    doc = {"fabric_settings": FORMAT, "exported": now.isoformat(timespec="seconds"),
           "from": {"site": site, "version": str(version)}, "settings": read_settings(v, have_gb)}
    text = ("# fabric's settings file (manual 1.8.5.4): the setup wizard's settings, no secret and no console-only "
            "setting.\n# Import: the web console's Settings, or sudo fabricctl settings import FILE\n"
            + yaml.safe_dump(doc, default_flow_style=False, sort_keys=False))
    return {"text": text, "name": f"{site}-settings.yaml"}
