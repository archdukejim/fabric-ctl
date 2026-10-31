import ldb

import paths


def remove_role(samdb, lp, site, name):
    """Purpose: a device role removed — refused while any device still names it, so no device silently loses (or
             keeps) access.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the role's name.
    Returns: {"name"}.
    Fails:   ValueError "role <name> still has <n> device(s); take them out first"; ldb.LdbError ERR_NO_SUCH_OBJECT,
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "remove_role")."""
    found = samdb.search(base=paths.folder_dn(samdb, "device-roles"), scope=ldb.SCOPE_SUBTREE,
                         expression=f"(&(objectClass=fabricRole)(cn={ldb.binary_encode(name)}))", attrs=["dn"])
    if not found:
        raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT, f"no role {name}")
    members = samdb.search(base=paths.folder_dn(samdb, "devices"), scope=ldb.SCOPE_ONELEVEL,
                           expression=f"(fabricRoleName={ldb.binary_encode(name)})", attrs=["cn"])
    if members:
        raise ValueError(f"role {name} still has {len(members)} device(s); take them out first")
    samdb.delete(str(found[0].dn))
    return {"name": name}
