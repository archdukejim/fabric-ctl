import os
import re
import subprocess

UNITS = "/etc/systemd/system"
SERVICE = """[Unit]
Description=fabric: the scheduled backup (manual 1.3.7.5)
After=docker.service fabric.target
Wants=docker.service

[Service]
Type=oneshot
# skipped, not failed, while setup is working or fabric is stopped (as every fabric timer's service)
ExecCondition=/bin/sh -c '! systemctl is-active --quiet fabric-setup.service && \
    systemctl is-active --quiet fabric.target'
ExecStart=/usr/bin/fabricctl backup --scheduled
"""
TIMER = """[Unit]
Description=fabric: the scheduled backup, daily at {time} (manual 1.3.7.5)

[Timer]
OnCalendar=*-*-* {time}:00
# a run missed while the host was off happens at boot
Persistent=true

[Install]
WantedBy=timers.target
"""


def install_backup_timer(v, units=UNITS, run=subprocess.run):
    """Purpose: fabric-backup.timer and its service as vars.yaml says (manual 1.3.7.5): on, at backup_schedule_time,
             while backup_public_key is set; removed (disabled first) while it is not.
    Inputs:  v — vars (backup_public_key, backup_schedule_time "HH:MM", default 03:00); units — systemd's unit folder;
             run — subprocess.run (tests).
    Returns: "on HH:MM" or "off".
    Fails:   ValueError for a time that is not HH:MM; OSError writing the units. systemctl's own failures are not
             raised (a host without systemd running keeps the files).
    Feeds:   set_backup_schedule, apply_deployment."""
    service, timer = (os.path.join(units, f"fabric-backup.{k}") for k in ("service", "timer"))
    if not v.get("backup_public_key"):
        if os.path.exists(timer):
            run(["systemctl", "disable", "--now", "fabric-backup.timer"], capture_output=True)
        for path in (service, timer):
            if os.path.exists(path):
                os.remove(path)
        run(["systemctl", "daemon-reload"], capture_output=True)
        return "off"
    when = v.get("backup_schedule_time") or "03:00"
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", when):
        raise ValueError(f"backup_schedule_time {when!r} is not HH:MM")
    for path, text in ((service, SERVICE), (timer, TIMER.format(time=when))):
        with open(path + ".tmp", "w") as f:
            f.write(text)
        os.chmod(path + ".tmp", 0o644)
        os.replace(path + ".tmp", path)
    run(["systemctl", "daemon-reload"], capture_output=True)
    run(["systemctl", "enable", "--now", "fabric-backup.timer"], capture_output=True)
    return f"on {when}"
