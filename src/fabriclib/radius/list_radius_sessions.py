import datetime
import json
import re
import subprocess
import urllib.parse

ACCT_RE = re.compile(r"fabric: ACCT (.*)$")
ACCEPT_RE = re.compile(r"fabric: ACCEPT method=(\S+)(.*)$")
WINDOW = "-26h"                    # a session with no record for this long is taken as gone


def _journal():
    """Purpose: FreeRADIUS's journal entries of the last WINDOW, oldest first.
    Inputs:  none; runs journalctl -t freeradius --since WINDOW -o json.
    Returns: list of (datetime, message str).
    Fails:   FileNotFoundError without journalctl; subprocess.TimeoutExpired after 30 s. Unparseable lines skipped.
    Feeds:   list_radius_sessions."""
    res = subprocess.run(["journalctl", "-t", "freeradius", "--since", WINDOW, "-o", "json", "--no-pager"],
                         capture_output=True, text=True, timeout=30)
    out = []
    for line in res.stdout.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        msg = rec.get("MESSAGE") if isinstance(rec.get("MESSAGE"), str) else ""
        out.append((datetime.datetime.fromtimestamp(int(rec.get("__REALTIME_TIMESTAMP", 0)) / 1e6), msg))
    return out


def list_radius_sessions(records=None):
    """Purpose: the open 802.1X sessions, from the accounting lines fabric's policy logs (`fabric: ACCT …`, manual
             1.11.1.4): the latest record per client and Acct-Session-Id, open until a Stop; who it is and its VLAN
             from the latest ACCEPT for its MAC.
    Inputs:  records — list of (datetime, message) oldest first; None reads the journal (the last 26 hours).
    Returns: list of {"client", "session", "mac", "nas_ip", "port", "user", "ip", "status" (Start / Interim-Update),
             "since" (the session's first record, ISO), "seen" (its latest), "who" (the device or person from the
             latest ACCEPT for its MAC, or "-"), "person" (bool), "method", "vlan"}, newest first. A session whose
             latest record is a Stop (or Accounting-Off from its client) is left out.
    Fails:   FileNotFoundError / subprocess.TimeoutExpired from the journal when records is None.
    Feeds:   radius_sessions, coa_session.
    """
    sessions, accepted = {}, {}
    for when, msg in (_journal() if records is None else records):
        m = ACCEPT_RE.search(msg or "")
        if m:
            kv = dict(p.split("=", 1) for p in m.group(2).split() if "=" in p)
            if kv.get("mac"):
                accepted[kv["mac"]] = {"who": kv.get("device") or kv.get("person") or kv.get("machine") or "-",
                                       "person": "person" in kv, "method": m.group(1), "vlan": kv.get("vlan", "-")}
            continue
        m = ACCT_RE.search(msg or "")
        if not m:
            continue
        kv = {k: urllib.parse.unquote(v) for k, v in (p.split("=", 1) for p in m.group(1).split() if "=" in p)}
        status = kv.get("status", "-")
        if status in ("Accounting-Off", "Accounting-On"):   # the client restarted: all its sessions are gone
            for key in [k for k in sessions if k[0] == kv.get("client")]:
                sessions.pop(key)
            continue
        key = (kv.get("client", "-"), kv.get("session", "-"))
        if key[1] in ("-", ""):
            continue
        if status == "Stop":
            sessions.pop(key, None)
            continue
        since = sessions.get(key, {}).get("since") or when.isoformat(timespec="seconds")
        sessions[key] = {"client": key[0], "session": key[1], "mac": kv.get("mac", "-"),
                         "nas_ip": kv.get("nas_ip", "-"), "port": kv.get("port", "-"), "user": kv.get("user", "-"),
                         "ip": kv.get("ip", "-"), "status": status, "since": since,
                         "seen": when.isoformat(timespec="seconds")}
    out = []
    for s in sessions.values():
        who = accepted.get(s["mac"], {"who": "-", "person": False, "method": "-", "vlan": "-"})
        out.append({**s, **who})
    return sorted(out, key=lambda s: s["seen"], reverse=True)
