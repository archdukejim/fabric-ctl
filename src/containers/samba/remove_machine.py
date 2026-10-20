from find_machine import find_machine


def remove_machine(samdb, lp, site, name):
    """Purpose: remove a machine from the domain (manual 1.6.7.6): its account and what it holds.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the host name.
    Returns: {"name"}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT (no such machine in OU=machines or OU=fabric-hosts),
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "remove_machine")."""
    samdb.delete(find_machine(samdb, name).dn, ["tree_delete:1"])
    return {"name": name}
