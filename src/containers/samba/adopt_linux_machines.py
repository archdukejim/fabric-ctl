import ldb

import paths
from site_roles import CLASSES

# what an unmanaged join writes on the account (join-linux.sh --unmanaged; add-machine --unmanaged)
UNMANAGED = "fabric: unmanaged (manual 1.6.11.6)"


def adopt_linux_machines(samdb, lp, site, skip=()):
    """Purpose: a Linux machine joined with a site admin's password lands in its class's OU=linux on its own
             (`OU=linux,OU=<servers|desktops>,OU=machines`, join-linux.sh); make each
             one found there a member of <site>-fabric-machines, once (manual 1.6.11.6, 2.1.6.40): not one marked
             unmanaged by its join, not one already a member, not one adopted before (an admin who takes a machine out
             keeps it out).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; skip — objectGUIDs (str) of
             machines adopted before.
    Returns: [{"name", "guid"}] the machines made members now.
    Fails:   ldb.LdbError from the search or a change AD refuses.
    Feeds:   directory_ops (op "adopt_linux_machines")."""
    site_dn = paths.site_dn(samdb, site)
    group = f"{site}-fabric-machines"
    found = []
    for ou in CLASSES.values():          # each class's OU=linux (2.1.6.36 as revised 2026-10-13)
        try:
            found += samdb.search(base=f"OU=linux,OU={ou},OU=machines,{site_dn}", scope=ldb.SCOPE_ONELEVEL,
                                  expression="(objectClass=computer)",
                                  attrs=["objectGUID", "sAMAccountName", "description", "memberOf"])
        except ldb.LdbError as e:
            if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:      # an OU not converged yet holds nothing
                raise
    skip = {g.lower() for g in skip}
    adopted = []
    for m in found:
        guid = str(samdb.schema_format_value("objectGUID", m["objectGUID"][0]), "utf-8")
        if guid.lower() in skip or str(m.get("description", [""])[0]) == UNMANAGED \
                or any(str(g).lower().startswith(f"cn={group.lower()},") for g in m.get("memberOf", [])):
            continue
        samdb.add_remove_group_members(group, [str(m["sAMAccountName"][0])], add_members_operation=True)
        adopted.append({"name": str(m["sAMAccountName"][0]).rstrip("$").lower(), "guid": guid})
    return adopted
