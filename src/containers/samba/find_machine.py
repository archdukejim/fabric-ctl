import ldb

from all_machines import all_machines


def find_machine(samdb, name):
    """Purpose: a machine by its name, in any OU of the domain since 0.9.1 (1.8.8.5: a machine moved to an admin's OU
             is still found): OU=machines and below, OU=fabric-hosts, an admin's own OU anywhere; never a domain
             controller or an account in AD's own containers (all_machines).
    Inputs:  samdb — SamDB; name — the host name (any case).
    Returns: ldb.Message (dn, userAccountControl, memberOf).
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT when there is no such machine.
    Feeds:   set_machine, remove_machine, place_fabric_host, move_object, set_machine_type, set_machine_site,
             reaching_grants."""
    found = all_machines(samdb, f"(sAMAccountName={ldb.binary_encode(name)}$)", ["memberOf"])
    if found:
        return found[0]
    raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT, f"no machine {name}")
