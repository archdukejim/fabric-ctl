import ldb

import paths

ATTRS = ["userAccountControl", "memberOf", "lockoutTime"]


def find_person(samdb, uid):
    """Purpose: a person by user name, in OU=people (any folder below it, 2.1.6.64): never a service account, which
             lives in OU=service-accounts (manual 1.6.3.16, 1.6.13.2).
    Inputs:  samdb — SamDB; uid — the user name.
    Returns: ldb.Message (dn, userAccountControl, memberOf, lockoutTime).
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT when there is no such person.
    Feeds:   set_person, remove_person, get_person, reset_password, ensure_enterprise_admin, reset_break_glass."""
    found = samdb.search(base=paths.folder_dn(samdb, "people"), scope=ldb.SCOPE_SUBTREE,
                         expression=f"(&(objectCategory=person)(objectClass=user)"
                                    f"(sAMAccountName={ldb.binary_encode(uid)}))", attrs=ATTRS)
    if not found:
        raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT, f"no person {uid}")
    return found[0]
