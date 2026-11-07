import ldb

from alloc_id import alloc_id
from group_names import site_group
from may_hold import may_hold
import paths

PERSON_KINDS = ("person", "first_admin", "admin", "guest")      # the ranges a person's uid may come from


def create_person(samdb, lp, site, uid, first, last, email, password, gid, home_base, shell, must_change=True,
                  kind="person", dc="", ou=""):
    """Purpose: a new person (manual 1.6.13.2, 1.6.3.9; 2.1.6.64): a user in OU=people, flat, named by its user name
             (or in the OU Create in... names, 2.1.6.101, where may_hold lets a person be),
             with their POSIX identity (a uid from the DC's range, never reused, 2.1.6.63), a member of their site's
             group `site-<site>` (1.6.13.3), and a one-time password they must change at their first sign-in (or, for
             the first admin, the password they chose in setup: 2.1.6.33).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str, the site they are put in; uid — the
             user name (checked by the caller); first, last — str; email — str, or ""/None for none; password — the
             one-time password (it must
             satisfy the domain's policy); gid — int, their primary gid (fabric's users); home_base — str (e.g.
             /home); shell — str (e.g. /bin/bash); must_change — False only for a password the person chose themselves
             (the first admin's, in setup); kind — which range the uid comes from (2.1.6.46): person (default),
             first_admin (setup's first admin), admin, guest; dc — the DC whose range it comes from (the request's);
             ou — an OU's path, or "" for OU=people.
    Returns: {"uid", "uidNumber"}.
    Fails:   ldb.LdbError ERR_ENTRY_ALREADY_EXISTS when the user name or the e-mail address is taken anywhere in the
             domain; ERR_CONSTRAINT_VIOLATION when the policy refuses the password; ERR_INSUFFICIENT_ACCESS_RIGHTS;
             ValueError when the DC's range of the kind is full (and its site's other DCs'), for a kind that is
             not a person's, or an OU a person may not be put in (may_hold).
    Feeds:   directory_ops (op "create_person")."""
    base = str(samdb.domain_dn())
    email = email or None                    # none on record (2.1.6.93: the first admin's is optional)
    mail = f"(mail={ldb.binary_encode(email)})" if email else ""
    taken = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE,
                         expression=f"(|(sAMAccountName={ldb.binary_encode(uid)}){mail})", attrs=["dn"])
    if taken:
        raise ldb.LdbError(ldb.ERR_ENTRY_ALREADY_EXISTS, f"{uid} (or that e-mail address) already exists")
    if kind not in PERSON_KINDS:
        raise ValueError(f"a person's id kind is one of {', '.join(PERSON_KINDS)}, not {kind!r}")
    where = may_hold(samdb, "person", ou) if ou else paths.folder_dn(samdb, "people")
    number = alloc_id(samdb, dc, kind)
    samdb.newuser(uid, password, force_password_change_at_next_login_req=must_change, useusernameascn=True,
                  userou=paths.relative(samdb, where), givenname=first or None,
                  surname=last or None,
                  mailaddress=email,
                  uidnumber=number, gidnumber=gid, loginshell=shell, unixhome=f"{home_base}/{uid}", uid=uid)
    samdb.add_remove_group_members(site_group(site), [uid], add_members_operation=True)
    return {"uid": uid, "uidNumber": number}
