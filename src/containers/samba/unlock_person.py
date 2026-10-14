import ldb


def unlock_person(samdb, lp, site, uid):
    """Purpose: a person's account unlocked after too many wrong passwords (manual 1.6.3.18, 2.1.9.21): lockoutTime
             back to 0, their password left as it is (a reset is reset_password).
    Inputs:  samdb — SamDB (as the site's agent: AD refuses a person outside the agent's site); lp — LoadParm
             (unused); site — str (unused); uid — the user name.
    Returns: {"uid", "unlocked" (bool: false when the account was not locked)}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT for no such person (service accounts are not people);
             ERR_INSUFFICIENT_ACCESS_RIGHTS outside the agent's site.
    Feeds:   directory_ops (op "unlock_person")."""
    found = samdb.search(base=f"OU=sites,{samdb.domain_dn()}", scope=ldb.SCOPE_SUBTREE,
                         expression=f"(&(objectCategory=person)(objectClass=user)"
                                    f"(sAMAccountName={ldb.binary_encode(uid)}))", attrs=["lockoutTime"])
    if not found or ",OU=service-accounts," in str(found[0].dn):
        raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT, f"no user {uid}")
    if not int(str(found[0].get("lockoutTime", ["0"])[0])):
        return {"uid": uid, "unlocked": False}
    samdb.modify(ldb.Message.from_dict(samdb, {"dn": str(found[0].dn), "lockoutTime": "0"}, ldb.FLAG_MOD_REPLACE))
    return {"uid": uid, "unlocked": True}
