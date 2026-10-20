import ldb


def find_gpo(samdb, name):
    """Purpose: a GPO found by its display name (fabric's names are its own).
    Inputs:  samdb — SamDB; name — str.
    Returns: (dn str, guid "{…}" str, versionNumber int) or None.
    Fails:   ldb.LdbError from the search.
    Feeds:   ensure_gpo."""
    res = samdb.search(base=f"CN=Policies,CN=System,{samdb.domain_dn()}", scope=ldb.SCOPE_ONELEVEL,
                       expression=f"(&(objectClass=groupPolicyContainer)(displayName={ldb.binary_encode(name)}))",
                       attrs=["cn", "versionNumber"])
    if not res:
        return None
    return str(res[0].dn), str(res[0]["cn"]), int(str(res[0].get("versionNumber", ["0"])[0]))
