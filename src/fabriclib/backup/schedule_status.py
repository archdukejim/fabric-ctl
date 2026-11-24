import subprocess

FIELDS = {"timer": ("NextElapseUSecRealtime", "LastTriggerUSec"),
          "service": ("Result", "ExecMainStatus", "ExecMainExitTimestamp")}


def _show(unit, props, run):
    """Purpose: some of a unit's properties as systemd says them.
    Inputs:  unit — a unit's name; props — property names; run — subprocess.run.
    Returns: {name: value}, values "" when systemd does not know them (or is not running).
    Fails:   never.
    Feeds:   schedule_status."""
    try:
        res = run(["systemctl", "show", unit, *(f"--property={p}" for p in props)], capture_output=True, text=True,
                  timeout=10)
    except (OSError, subprocess.SubprocessError):
        return {p: "" for p in props}
    found = dict(line.split("=", 1) for line in (res.stdout or "").splitlines() if "=" in line)
    return {p: found.get(p, "").strip() for p in props}


def schedule_status(v, run=subprocess.run):
    """Purpose: the backup schedule as the console's Backups page shows it (manual 1.3.7.9): its settings from vars.yaml
             and its runs from systemd (the timer's next and last trigger, the service's last result).
    Inputs:  v — vars (backup_public_key, backup_schedule_time, backup_keep); run — subprocess.run (tests).
    Returns: {"on": bool, "time", "keep", "public_key", "next", "last", "last_result": "ok" | "failed" | ""}: next and
             last are systemd's words ("" when it has none, or the schedule is off); last_result "" before a first
             run.
    Fails:   never (a host without systemd running shows no runs).
    Feeds:   agent/get_backup."""
    on = bool(v.get("backup_public_key"))
    out = {"on": on, "time": str(v.get("backup_schedule_time") or "03:00"), "keep": int(v.get("backup_keep") or 7),
           "public_key": v.get("backup_public_key") or "", "next": "", "last": "", "last_result": ""}
    if not on:
        return out
    timer = _show("fabric-backup.timer", FIELDS["timer"], run)
    service = _show("fabric-backup.service", FIELDS["service"], run)
    out["next"] = "" if timer["NextElapseUSecRealtime"] in ("", "n/a") else timer["NextElapseUSecRealtime"]
    out["last"] = "" if timer["LastTriggerUSec"] in ("", "n/a") else timer["LastTriggerUSec"]
    if service["ExecMainExitTimestamp"] not in ("", "n/a"):
        out["last_result"] = "ok" if service["Result"] == "success" and service["ExecMainStatus"] in ("", "0") \
            else "failed"
    return out
