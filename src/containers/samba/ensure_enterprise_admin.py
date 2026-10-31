"""The Enterprise Admin, `fabric-admin` (manual 1.6.12.2; 2.1.6.68, 2.1.6.69): made once by setup at the root's DC, as
root, on the DC's own database (fabric's agent accounts may not change AD's top tier, and never should).
    docker exec -i samba python3 /fabric/ensure_enterprise_admin.py < request.json
The request on stdin: {"password", "dc", "gid", "home_base", "shell", optional "policies"}. Prints one JSON object:
{"created": bool, "changed": [what changed, ...]}. Exits 1 with the error on stderr. The password comes only on stdin,
never printed."""
import json
import sys

import ldb

from alloc_id import alloc_id
from ensure_tier_policies import ensure_tier_policies
from ensure_top_tier import ensure_top_tier
from find_person import find_person
from open_samdb import open_samdb
import paths

CONF = "/data/etc/smb.conf"
NAME = "fabric-admin"


def ensure_enterprise_admin(samdb, password, dc, gid, home_base, shell, policies=None):
    """Purpose: `fabric-admin` as the Enterprise Admin (2.1.6.68): made when missing, in OU=people, with the generated
             password (no change asked at the first sign-in), its POSIX identity from the DC range's first id
             (first_admin, 2.1.6.46) and in no site's group (it is nobody's everyday account); then a member of
             Enterprise, Schema and Domain Admins, with the top tier's denies written (ensure_top_tier), and the
             tiers' password policies written at once (ensure_tier_policies: its own lockout from the start). An
             existing account keeps its password. It is never made a Directory Administrator (directory-admins).
    Inputs:  samdb — SamDB (as the system); password — the generated password; dc — this DC (dc-NNNN, its range);
             gid — int, its primary gid (fabric's users); home_base — str; shell — str; policies — the tiers'
             password policies (ad_tier_password_policies) or None (none written).
    Returns: (created bool, list of str, what changed).
    Fails:   ldb.LdbError from a change (ERR_CONSTRAINT_VIOLATION: the domain's policy refused the password);
             ValueError when the DC's ranges are full.
    Feeds:   this script's main."""
    done, created = [], False
    try:
        find_person(samdb, NAME)
    except ldb.LdbError:
        # the account first: a password the policy refuses takes no id (ids are never reused, 2.1.6.63)
        samdb.newuser(NAME, password, force_password_change_at_next_login_req=False, useusernameascn=True,
                      userou=paths.relative(samdb, paths.folder_dn(samdb, "people")), givenname="fabric",
                      surname="admin")
        number = alloc_id(samdb, dc, "first_admin")
        samdb.modify(ldb.Message.from_dict(samdb, {
            "dn": str(find_person(samdb, NAME).dn), "displayName": "fabric-admin (Enterprise Admin, break glass)",
            "description": "fabric: the Enterprise Admin, for break glass only (manual 1.6.12.2)",
            "uidNumber": str(number), "gidNumber": str(gid), "loginShell": shell,
            "unixHomeDirectory": f"{home_base}/{NAME}", "uid": NAME}, ldb.FLAG_MOD_REPLACE))
        created = True
        done.append(f"{NAME} created in OU=people (uid {number})")
    done += ensure_top_tier(samdb, NAME)
    return created, done + (ensure_tier_policies(samdb, policies) if policies else [])


if __name__ == "__main__":
    try:
        request = json.load(sys.stdin)
        db, _ = open_samdb(CONF)
        made, changed = ensure_enterprise_admin(db, request["password"], request["dc"], int(request["gid"]),
                                                request["home_base"], request["shell"], request.get("policies"))
    except Exception as e:                  # the caller reports it; the DC keeps running (never the password)
        print(f"{type(e).__name__}: {str(e)[:300]}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"created": made, "changed": changed}))
