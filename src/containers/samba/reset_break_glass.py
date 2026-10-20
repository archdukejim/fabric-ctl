"""A lost break-glass password replaced (manual 1.6.13.6; 2.1.6.75), run by `fabricctl admin reset-break-glass` as
root on a host with a writable DC, inside that DC as the system.
    docker exec -i samba python3 /fabric/reset_break_glass.py < request.json
The request on stdin: {"password"}. Prints one JSON object: {"changed": [what changed, ...], "disabled": bool}. Exits 1
with the error on stderr. The password comes only on stdin and is never printed."""
import json
import sys

import ldb

from find_person import find_person
from open_samdb import open_samdb

CONF = "/data/etc/smb.conf"
NAME = "fabric-admin"
ACCOUNTDISABLE = 0x2


def reset_break_glass(samdb, password):
    """Purpose: `fabric-admin`'s new generated password set (no change asked at the next sign-in) and the account
             unlocked (lockoutTime 0, which clears its failed sign-ins too). fabric never disables or enables it
             (2.1.6.69): a disabled account is reported, not changed.
    Inputs:  samdb — SamDB (as the system); password — the new generated password.
    Returns: (list of str, what changed; bool, whether the account is disabled).
    Fails:   ValueError "no fabric-admin in OU=people"; ldb.LdbError from a change (the policy refusing the password).
    Feeds:   this script's main."""
    try:
        msg = find_person(samdb, NAME)
    except ldb.LdbError:
        raise ValueError(f"no {NAME} in OU=people (setup makes it at the root site)") from None
    samdb.setpassword(f"(sAMAccountName={NAME})", password, force_change_at_next_login=False, username=NAME)
    done = [f"{NAME}: a new password"]
    if int(str(msg.get("lockoutTime", ["0"])[0]) or 0):
        done.append(f"{NAME}: unlocked")
    samdb.modify(ldb.Message.from_dict(samdb, {"dn": str(msg.dn), "lockoutTime": "0"}, ldb.FLAG_MOD_REPLACE))
    return done, bool(int(str(msg.get("userAccountControl", ["0"])[0])) & ACCOUNTDISABLE)


if __name__ == "__main__":
    try:
        db, _ = open_samdb(CONF)
        changed, disabled = reset_break_glass(db, json.load(sys.stdin)["password"])
    except Exception as e:                  # the caller reports it; the DC keeps running (never the password)
        print(f"{type(e).__name__}: {str(e)[:300]}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"changed": changed, "disabled": disabled}))
