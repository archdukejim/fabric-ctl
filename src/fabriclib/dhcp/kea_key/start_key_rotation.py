import datetime

from fabriclib.dhcp.kea_key.kea_key import ROTATE_DAYS, kea_key
from fabriclib.secrets.random_secret import random_secret


def _new_name(today, taken):
    """Purpose: the new key's name: "kea-ddns-<YYYYMMDD>", a suffix added when that is taken (two replacements on one
             day), so BIND can know the old key and the new one side by side.
    Inputs:  today — datetime.date; taken — the names in use.
    Returns: str, one DNS label.
    Fails:   never.
    Feeds:   start_key_rotation."""
    name = f"kea-ddns-{today:%Y%m%d}"
    n = 2
    while name in taken:
        name, n = f"kea-ddns-{today:%Y%m%d}-{n}", n + 1
    return name


def start_key_rotation(v, secrets, due=True, force=False, today=None):
    """Purpose: the first step of replacing Kea's DNS key (decision 2.1.10.42, manual 1.10.4.43), made in fabric's
             secrets before an apply renders: a new key (new name, new 256-bit secret) becomes Kea's, the old one is
             kept as kea_ddns_old so BIND knows both until Kea runs on the new (the apply then drops it,
             drop_old_key). A key not dated yet is dated today (the clock starts at the first apply that sees it).
             Nothing is started while a replacement is under way: that apply finishes it.
    Inputs:  v — the settings (install_kea, dhcp.ddns); secrets — fabric's secrets, changed in place; due — whether
             this run may replace a key that is ROTATE_DAYS old (an apply that starts services: True; setup's first
             deploy, DNS' own Apply: False); force — replace it whatever its age (`fabricctl dhcp rotate-key`);
             today — datetime.date (default: today, UTC).
    Returns: {"changed": bool (secrets changed: save them), "started": a sentence saying what is replaced and why,
             or None}.
    Fails:   never.
    Feeds:   deploy/render_deployment (each apply, before the render), rotate_key."""
    d = v.get("dhcp") or {}
    if not v.get("install_kea") or not d.get("ddns", True) or not secrets.get("kea_ddns_secret"):
        return {"changed": False, "started": None}
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    key = kea_key(secrets, today)
    if key["old"]:                               # under way: the apply that renders now finishes it
        return {"changed": False, "started": None}
    if key["made"] is None and not force:
        secrets["kea_ddns_made"] = today.isoformat()
        return {"changed": True, "started": None}
    if not force and not (due and key["age"] >= ROTATE_DAYS):
        return {"changed": False, "started": None}
    name = _new_name(today, {key["name"]})
    secrets["kea_ddns_old"] = {"name": key["name"], "secret": key["secret"], "made": key["made"]}
    secrets.update(kea_ddns_key=name, kea_ddns_secret=random_secret(32), kea_ddns_made=today.isoformat())
    why = "asked for" if force else f"{key['age']} days old, replaced from day {ROTATE_DAYS}"
    return {"changed": True, "started": f"Kea's DNS key {key['name']} ({why}) is replaced by {name}: BIND knows both "
                                        "until Kea runs on the new one"}
