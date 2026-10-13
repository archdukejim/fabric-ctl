import ldb

from paths import site_dn

# where a site's computer accounts live: its machines, and its fabric host beside them (manual 1.6.11.11)
MACHINE_OUS = ("machines", "fabric-hosts")


def find_machine(samdb, site, name):
    """Purpose: a machine of the site by its name, in its OU=machines (and the OUs below) or its OU=fabric-hosts.
    Inputs:  samdb — SamDB; site — str; name — the host name (any case).
    Returns: ldb.Message (dn, userAccountControl).
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT when the site has no such machine.
    Feeds:   set_machine, remove_machine."""
    base = site_dn(samdb, site)
    for ou in MACHINE_OUS:
        try:
            found = samdb.search(base=f"OU={ou},{base}", scope=ldb.SCOPE_SUBTREE,
                                 expression=f"(&(objectCategory=computer)(sAMAccountName={ldb.binary_encode(name)}$))",
                                 attrs=["userAccountControl"])
        except ldb.LdbError as e:
            if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:     # an OU not converged yet: nothing in it
                continue
            raise
        if found:
            return found[0]
    raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT, f"no machine {name} in site {site}")
