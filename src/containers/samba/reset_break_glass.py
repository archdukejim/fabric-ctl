"""A lost break-glass password replaced (manual 1.6.13.6; 2.1.6.75), run by `fabricctl admin reset-break-glass` as
root on a host with a writable DC, inside that DC as the system.
    docker exec -i samba python3 /fabric/reset_break_glass.py < request.json
The request on stdin: {"password"}. Prints one JSON object: {"changed": [what changed, ...], "disabled": bool,
"locked_until": the end of a lockout in force, or null}. Exits 1
with the error on stderr. The password comes only on stdin and is never printed."""
import datetime
import json
import sys

import ldb

from find_person import find_person
from open_samdb import open_samdb

CONF = "/data/etc/smb.conf"
NAME = "fabric-admin"
ACCOUNTDISABLE = 0x2
UF_LOCKOUT = 0x10                   # msDS-User-Account-Control-Computed: locked out now


def _locked_until(samdb, dn):
    """Purpose: when a lockout of the account ends, if it is locked out now: its lockoutTime plus the lockout duration
             of the password policy that applies to it (its fine-grained policy, else the domain's).
    Inputs:  samdb — SamDB; dn — the account's DN.
    Returns: str, the end in UTC (ISO 8601, seconds), or None when it is not locked out.
    Fails:   ldb.LdbError from a search.
    Feeds:   reset_break_glass."""
    me = samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                      attrs=["lockoutTime", "msDS-User-Account-Control-Computed", "msDS-ResultantPSO"])[0]
    since = int(str(me.get("lockoutTime", ["0"])[0]) or 0)
    if not since or not int(str(me.get("msDS-User-Account-Control-Computed", ["0"])[0]) or 0) & UF_LOCKOUT:
        return None
    pso = me.get("msDS-ResultantPSO")
    if pso:
        held = samdb.search(base=str(pso[0]), scope=ldb.SCOPE_BASE, attrs=["msDS-LockoutDuration"])[0]
        duration = int(str(held["msDS-LockoutDuration"][0]))
    else:
        held = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_BASE, attrs=["lockoutDuration"])[0]
        duration = int(str(held["lockoutDuration"][0]))
    end = since + abs(duration)                      # 100-ns intervals since 1601 (AD's FILETIME)
    return datetime.datetime.fromtimestamp(end / 10_000_000 - 11644473600, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def reset_break_glass(samdb, password):
    """Purpose: `fabric-admin`'s new generated password set (no change asked at the next sign-in). Nothing else
             changes (2.1.6.92): a lockout in force runs its time out (the new password works from its end, said), and
             fabric never disables or enables the account (2.1.6.69): a disabled one is reported, not changed.
    Inputs:  samdb — SamDB (as the system); password — the new generated password.
    Returns: (list of str, what changed; bool, whether the account is disabled; str or None, when its lockout ends).
    Fails:   ValueError "no fabric-admin in OU=people"; ldb.LdbError from a change (the policy refusing the password).
    Feeds:   this script's main."""
    try:
        msg = find_person(samdb, NAME)
    except ldb.LdbError:
        raise ValueError(f"no {NAME} in OU=people (setup makes it at the root site)") from None
    samdb.setpassword(f"(sAMAccountName={NAME})", password, force_change_at_next_login=False, username=NAME)
    return ([f"{NAME}: a new password"], bool(int(str(msg.get("userAccountControl", ["0"])[0])) & ACCOUNTDISABLE),
            _locked_until(samdb, str(msg.dn)))


if __name__ == "__main__":
    try:
        db, _ = open_samdb(CONF)
        changed, disabled, locked_until = reset_break_glass(db, json.load(sys.stdin)["password"])
    except Exception as e:                  # the caller reports it; the DC keeps running (never the password)
        print(f"{type(e).__name__}: {str(e)[:300]}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"changed": changed, "disabled": disabled, "locked_until": locked_until}))
