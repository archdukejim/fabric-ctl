import ldb

from directory_scope import find_people

ATTRS = ["userAccountControl", "memberOf", "lockoutTime"]


def find_person(samdb, uid):
    """Purpose: a person by user name, in any OU (2.1.6.106): never a service account, which lives in
             OU=service-accounts (manual 1.6.3.16, 1.6.13.2), nor one of AD's own.
    Inputs:  samdb — SamDB; uid — the user name.
    Returns: ldb.Message (dn, userAccountControl, memberOf, lockoutTime).
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT when there is no such person.
    Feeds:   set_person, remove_person, get_person, reset_password, ensure_enterprise_admin, reset_break_glass."""
    found = find_people(samdb, f"(sAMAccountName={ldb.binary_encode(uid)})", ATTRS)
    if not found:
        raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT, f"no person {uid}")
    return found[0]
