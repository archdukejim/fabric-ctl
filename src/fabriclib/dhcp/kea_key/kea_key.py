import datetime

DEFAULT_NAME = "kea-ddns"       # the key made at install, before any replacement (2.1.10.42)
ROTATE_DAYS = 330               # an apply replaces the key once it is this old (2.1.10.42)
REMIND_DAYS = 300               # doctor reminds from this age
YEAR_DAYS = 365                 # the BIND STIG's limit (V-272414, checklist row BIND-12): doctor fails past it


def kea_key(secrets, today=None):
    """Purpose: Kea's DNS key as fabric's secrets hold it (decision 2.1.10.42, manual 1.10.4.43): the key Kea signs
             with, when it was made, and the one being replaced while BIND still knows it.
    Inputs:  secrets — fabric's secrets (kea_ddns_key: its name, absent for the install's "kea-ddns";
             kea_ddns_secret; kea_ddns_made: "YYYY-MM-DD", absent until an apply dates it; kea_ddns_old: {"name",
             "secret", "made"} while a replacement is under way); today — datetime.date (default: today, UTC).
    Returns: {"name", "secret", "made" ("YYYY-MM-DD" or None), "age" (whole days, or None when not dated), "old"
             (dict or None)}.
    Fails:   never: a made date that does not read counts as not dated.
    Feeds:   start_key_rotation, key_reminders, rotate_key, deploy/restart_changed and dhcp/clean_dhcp_names (the
             key name nsupdate signs with)."""
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    made = secrets.get("kea_ddns_made") or None
    try:
        age = (today - datetime.date.fromisoformat(str(made))).days if made else None
    except ValueError:
        made, age = None, None
    return {"name": secrets.get("kea_ddns_key") or DEFAULT_NAME, "secret": secrets.get("kea_ddns_secret") or "",
            "made": made, "age": age, "old": secrets.get("kea_ddns_old") or None}
