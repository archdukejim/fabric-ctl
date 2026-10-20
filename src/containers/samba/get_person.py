from find_person import find_person


def get_person(samdb, lp, site, uid):
    """Purpose: one person by user name, in OU=people: where they live and the groups they are in (what a reset's
             guard needs, manual 1.6.3.8).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); uid — the user name.
    Returns: {"uid", "dn", "groups" [names]}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT when there is no such person (service accounts are not people).
    Feeds:   directory_ops (op "get_person")."""
    p = find_person(samdb, uid)
    return {"uid": uid, "dn": str(p.dn),
            "groups": sorted(str(g).split(",", 1)[0].split("=", 1)[1] for g in p.get("memberOf", []))}
