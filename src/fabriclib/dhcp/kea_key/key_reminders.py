from fabriclib.dhcp.kea_key.kea_key import REMIND_DAYS, ROTATE_DAYS, YEAR_DAYS, kea_key


def key_reminders(v, secrets, today=None):
    """Purpose: what `fabricctl doctor` says of Kea's DNS key (decision 2.1.10.42, manual 1.10.4.43): a check that
             it was replaced within the STIG's year, and reminders from day 300, while it is due and while a
             replacement is under way.
    Inputs:  v — the settings (install_kea, dhcp.ddns); secrets — fabric's secrets; today — datetime.date (default:
             today, UTC).
    Returns: {"checks": [(name, passed, detail)], "warnings": [str]}; both empty with Kea or its DNS registration
             off.
    Fails:   never.
    Feeds:   setup/verify_install (doctor's checks and warnings)."""
    if not v.get("install_kea") or not (v.get("dhcp") or {}).get("ddns", True):
        return {"checks": [], "warnings": []}
    key = kea_key(secrets, today)
    now = "sudo fabricctl dhcp rotate-key replaces it now"
    warnings = []
    if key["old"]:
        warnings.append(f"Kea's DNS key {key['old']['name']} is being replaced by {key['name']}: BIND still accepts "
                        "both; the next apply finishes it (sudo fabricctl --apply)")
    elif key["age"] is None:
        warnings.append(f"Kea's DNS key {key['name']} is not dated yet: the next apply dates it, and replaces it "
                        f"from day {ROTATE_DAYS}")
    elif key["age"] >= ROTATE_DAYS:
        warnings.append(f"Kea's DNS key {key['name']} is {key['age']} days old: due, the next apply replaces it "
                        f"({now})")
    elif key["age"] >= REMIND_DAYS:
        warnings.append(f"Kea's DNS key {key['name']} is {key['age']} days old: an apply replaces it from day "
                        f"{ROTATE_DAYS} ({now})")
    late = key["age"] is not None and key["age"] > YEAR_DAYS and not key["old"]
    detail = (f"{key['name']} is {key['age']} days old: {now}" if late else
              f"{key['name']}, {key['age']} days old" if key["age"] is not None else f"{key['name']}, not dated yet")
    return {"checks": [("Kea's DNS key replaced within a year (BIND-12)", not late, detail)], "warnings": warnings}
