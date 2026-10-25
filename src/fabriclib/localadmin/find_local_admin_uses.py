import datetime
import json
import re
import struct
import subprocess

from fabriclib.localadmin.constants import USER, WTMP

# PAM's session lines (pam_unix, pam_systemd …): a session opened for local-admin, or one it opened (sudo, su)
SESSION_RE = re.compile(rf"session opened for user {re.escape(USER)}\b|\bby {re.escape(USER)}\(")
# glibc's struct utmp on Linux (384 bytes): type, pid, line, id, user, host, exit, session, tv_sec, tv_usec, addr
UTMP = struct.Struct("<h2xi32s4s32s256shhiii16s20s")
USER_PROCESS = 7


def _journal(since, run):
    """Purpose: the sign-in messages of the journal's auth and authpriv facilities since a time, local-admin's.
    Inputs:  since — aware datetime; run — subprocess.run.
    Returns: list of (aware datetime, how str).
    Fails:   never (no journalctl, or its failure: no uses from it).
    Feeds:   find_local_admin_uses."""
    try:
        res = run(["journalctl", "--no-pager", "-o", "json", f"--since=@{int(since.timestamp())}",
                   "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return []
    out = []
    for line in (res.stdout or "").splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        message = entry.get("MESSAGE")
        if not isinstance(message, str) or not SESSION_RE.search(message):
            continue
        when = datetime.datetime.fromtimestamp(int(entry.get("__REALTIME_TIMESTAMP", 0)) / 1e6,
                                               datetime.timezone.utc).replace(microsecond=0)
        if when >= since:
            out.append((when, f"{entry.get('SYSLOG_IDENTIFIER') or 'PAM'}: {message.strip()[:160]}"))
    return out


def _wtmp(since, path):
    """Purpose: local-admin's sign-ins in wtmp (USER_PROCESS records) since a time.
    Inputs:  since — aware datetime; path — the wtmp file.
    Returns: list of (aware datetime, how str); [] when the file is missing or not of 384-byte records.
    Fails:   never (an unreadable file: no uses from it).
    Feeds:   find_local_admin_uses."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []
    if not data or len(data) % UTMP.size:
        return []
    out = []
    for off in range(0, len(data), UTMP.size):
        kind, _pid, line, _id, user, host, _e1, _e2, _sess, sec, _usec, _addr, _ = UTMP.unpack_from(data, off)
        if kind != USER_PROCESS or user.split(b"\0", 1)[0].decode(errors="replace") != USER:
            continue
        when = datetime.datetime.fromtimestamp(sec, datetime.timezone.utc)
        if when >= since:
            tty = line.split(b"\0", 1)[0].decode(errors="replace")
            src = host.split(b"\0", 1)[0].decode(errors="replace")
            out.append((when, f"wtmp: signed in on {tty}" + (f" from {src}" if src else "")))
    return out


def find_local_admin_uses(since, run=subprocess.run, wtmp=WTMP):
    """Purpose: local-admin's uses since its password was set (decision 2.1.7.17, manual 1.7.1.4.4): its sign-ins as
             the journal's PAM session lines show them (a session opened for it, or one it opened) and as wtmp records
             them; no PAM change is made to see them.
    Inputs:  since — aware datetime (the current password's set_at); run — subprocess.run (tests give their own);
             wtmp — the wtmp file (tests give their own).
    Returns: list of (aware datetime, how str), the earliest first; [] when none.
    Fails:   never (a source that cannot be read gives nothing).
    Feeds:   check_local_admin."""
    return sorted(_journal(since, run) + _wtmp(since, wtmp))
