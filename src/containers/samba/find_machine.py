import ldb

import paths

# where the domain's computer accounts that fabric manages live: OU=machines (and its type OUs and an admin's below),
# and the fabric hosts beside them (manual 1.6.13.2, 1.6.11.11)
MACHINE_FOLDERS = ("machines", "fabric-hosts")


def find_machine(samdb, name):
    """Purpose: a machine by its name, in OU=machines (and every OU below it) or OU=fabric-hosts: never a domain
             controller or an account in AD's own containers.
    Inputs:  samdb — SamDB; name — the host name (any case).
    Returns: ldb.Message (dn, userAccountControl, memberOf).
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT when there is no such machine.
    Feeds:   set_machine, remove_machine, place_fabric_host."""
    for folder in MACHINE_FOLDERS:
        try:
            found = samdb.search(base=paths.folder_dn(samdb, folder), scope=ldb.SCOPE_SUBTREE,
                                 expression=f"(&(objectCategory=computer)(sAMAccountName={ldb.binary_encode(name)}$))",
                                 attrs=["userAccountControl", "memberOf"])
        except ldb.LdbError as e:
            if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:     # a folder not converged yet: nothing in it
                continue
            raise
        if found:
            return found[0]
    raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT, f"no machine {name}")
