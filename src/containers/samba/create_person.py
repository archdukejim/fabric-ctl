import ldb

from alloc_id import alloc_id
import paths

PERSON_KINDS = ("person", "first_admin", "admin", "guest")      # the ranges a person's uid may come from


def create_person(samdb, lp, site, uid, first, last, email, password, gid, home_base, shell, must_change=True,
                  kind="person"):
    """Purpose: a new person in a site (manual 1.6.3.4, 1.6.3.9, 1.6.3.10): a user in the site's OU=people named by
             its user name, with their POSIX identity (a uid from the site's block, never reused), a member of
             `<site>-users`, and a one-time password they must change at their first sign-in (or, for the first admin,
             the password they chose in setup: 2.1.6.33).
    Inputs:  samdb — SamDB (as the site's agent: AD refuses another site); lp — LoadParm (unused); site — str;
             uid — the user name (checked by the caller); first, last, email — str; password — the one-time
             password (it must satisfy the domain's policy); gid — int, their primary gid (fabric's users: 5000);
             home_base — str (e.g. /home); shell — str (e.g. /bin/bash); must_change — False only for a password the
             person chose themselves (the first admin's, in setup); kind — which range of a laid-out block the uid
             comes from (2.1.6.46): person (default), first_admin (setup's first admin), admin, guest.
    Returns: {"uid", "uidNumber"}.
    Fails:   ldb.LdbError ERR_ENTRY_ALREADY_EXISTS when the user name or the e-mail address is taken anywhere in the
             domain; ERR_CONSTRAINT_VIOLATION when the policy refuses the password; ERR_INSUFFICIENT_ACCESS_RIGHTS
             outside the agent's site; ValueError when the site's id block (or the kind's range) is full, or for
             a kind that is not a person's.
    Feeds:   directory_ops (op "create_person")."""
    base = str(samdb.domain_dn())
    taken = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE,
                         expression=f"(|(sAMAccountName={ldb.binary_encode(uid)})(mail={ldb.binary_encode(email)}))",
                         attrs=["dn"])
    if taken:
        raise ldb.LdbError(ldb.ERR_ENTRY_ALREADY_EXISTS, f"{uid} (or that e-mail address) already exists")
    if kind not in PERSON_KINDS:
        raise ValueError(f"a person's id kind is one of {', '.join(PERSON_KINDS)}, not {kind!r}")
    site_dn = paths.site_dn(samdb, site)
    number = alloc_id(samdb, site_dn, kind)
    samdb.newuser(uid, password, force_password_change_at_next_login_req=must_change, useusernameascn=True,
                  userou=paths.relative(samdb, f"OU=people,{site_dn}"), givenname=first, surname=last,
                  mailaddress=email,
                  uidnumber=number, gidnumber=gid, loginshell=shell, unixhome=f"{home_base}/{uid}", uid=uid)
    samdb.add_remove_group_members(f"{site}-users", [uid], add_members_operation=True)
    return {"uid": uid, "uidNumber": number}
