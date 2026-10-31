from find_person import find_person
from person_record import person_record


def get_person(samdb, lp, site, uid):
    """Purpose: one person by user name, in OU=people: where they live, the groups they are in (what a reset's guard
             needs, manual 1.6.3.8) and their details (AD's standard attributes, 2.1.6.93: a person's page, and
             the version of a pending change to them, 2.1.8.14).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); uid — the user name.
    Returns: {"uid", "dn", "groups" [names], "person": {field: value} (person_record's)}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT when there is no such person (service accounts are not people).
    Feeds:   directory_ops (op "get_person")."""
    p = find_person(samdb, uid)
    return {"uid": uid, "dn": str(p.dn),
            "groups": sorted(str(g).split(",", 1)[0].split("=", 1)[1] for g in p.get("memberOf", [])),
            "person": person_record(samdb, p.dn)}
