from find_person import find_person


def remove_person(samdb, lp, site, uid):
    """Purpose: remove a person from the domain (manual 1.6.3.16): their account and their group
             memberships; their POSIX uid is never given out again (alloc_id only counts up).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); uid — the user name.
    Returns: {"uid"}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT (no such person in OU=people), ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "remove_person")."""
    samdb.delete(find_person(samdb, uid).dn, ["tree_delete:1"])
    return {"uid": uid}
