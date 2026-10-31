import os
import re
import time

from fabriclib.dns.rndc import rndc

TOKEN = re.compile(r"[^\s()]+")


def _soa_fields(text):
    """Purpose: where a zone file's SOA serial and minimum (the negative-caching TTL) are, in fabric's one-line form
             or the several lines BIND writes (`( 123 ; serial` … `300 ; minimum (5 minutes)` … `)`).
    Inputs:  text — the zone file.
    Returns: ((serial start, end), (minimum start, end)) as offsets into text, or None when no SOA is read.
    Fails:   never.
    Feeds:   set_negative_ttl."""
    found, offset, numbers = False, 0, []
    for line in text.splitlines(keepends=True):
        code = line.split(";", 1)[0]
        for m in TOKEN.finditer(code):
            word = m.group(0)
            if not found:
                found = word.upper() == "SOA"
                names = 0
                continue
            if names < 2:                         # the primary server's and the mailbox's names
                names += 1
                continue
            if not word.isdigit():
                return None
            numbers.append((offset + m.start(), offset + m.end()))
            if len(numbers) == 5:
                return numbers[0], numbers[4]
        offset += len(line)
    return None


def _rewrite(path, ttl):
    """Purpose: the zone file with its SOA minimum set to ttl and its serial one higher, written in place.
    Inputs:  path — the zone file; ttl — int seconds.
    Returns: True when written, False when the SOA was not read (the file is left).
    Fails:   OSError reading or writing.
    Feeds:   set_negative_ttl."""
    with open(path) as f:
        text = f.read()
    at = _soa_fields(text)
    if at is None:
        return False
    (s0, s1), (m0, m1) = at
    serial = max(int(text[s0:s1]) + 1, int(time.time()) + 1000000000)
    text = text[:s0] + str(serial) + text[s1:m0] + str(ttl) + text[m1:]
    st = os.stat(path)
    with open(path, "w") as f:
        f.write(text)
    os.chown(path, st.st_uid, st.st_gid)
    return True


def _negative_ttl(path):
    """Purpose: a zone file's SOA minimum, the time resolvers keep "no such name" (RFC 2308).
    Inputs:  path — the zone file.
    Returns: int, or None when the file has no SOA fabric can read.
    Fails:   OSError reading the file.
    Feeds:   set_negative_ttl."""
    with open(path) as f:
        text = f.read()
    at = _soa_fields(text)
    return int(text[at[1][0]:at[1][1]]) if at else None


def set_negative_ttl(zone, path, ttl, call=rndc, wait=3.0):
    """Purpose: a zone fabric made once and does not render again (the DHCP subzone, written by Kea through BIND's
             journal: 2.1.4.1) given the negative-caching TTL fabric's zones have now (decision 2.1.4.9), the way an
             administrator edits a dynamic zone: `rndc freeze` (BIND writes its journal into the file), the SOA's
             minimum and serial changed, `rndc thaw` (BIND reads the file). What DHCP registered stays.
    Inputs:  zone — the zone's name; path — its file; ttl — int seconds; call — rndc (tests give their own); wait —
             how long to wait for BIND's write after the freeze.
    Returns: "already" (the minimum is ttl), "set" (changed, BIND reloaded it, or BIND is down and nothing waits in a
             journal), or "left: <why>" (BIND down with a journal newer than the file, or BIND refusing: the next
             apply tries again; nothing is changed).
    Fails:   OSError reading or writing the file.
    Feeds:   dhcp/ensure_ddns_zone (every apply)."""
    have = _negative_ttl(path)
    if have in (ttl, None):
        return "already" if have == ttl else "left: its SOA could not be read"
    before = os.stat(path).st_mtime_ns
    jnl = path + ".jnl"
    pending = os.path.exists(jnl) and os.stat(jnl).st_mtime_ns > before
    res = call(["freeze", zone])
    if res is None or res.returncode != 0:          # BIND not running: the file alone is safe without a journal
        if pending:
            return "left: BIND is not running and its journal holds changes the file does not"
        return "set" if _rewrite(path, ttl) else "left: its SOA could not be read"
    end = time.monotonic() + wait
    while pending and os.stat(path).st_mtime_ns == before and time.monotonic() < end:
        time.sleep(0.05)                            # `rndc freeze` answers before BIND's write is done (2.3.1.22)
    written = _rewrite(path, ttl)
    res = call(["thaw", zone])
    if res is None or res.returncode != 0:
        why = (res.stderr or res.stdout).strip() if res else "BIND did not answer"
        return f"left: BIND did not take the file back ({why}); the next apply tries again"
    return "set" if written else "left: its SOA could not be read"
