import ldb

from paths import devices_dn, site_dn, sites_dn


def remove_role(samdb, lp, site, name):
    """Purpose: a device role removed — refused while any of this site's devices, or any reservation of its address
             plan (MAB from a reservation, manual 1.11.1.7; decision 2.1.11.9), still names it, so no device silently
             loses (or keeps) access.
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; name — the role's name.
    Returns: {"name"}.
    Fails:   ValueError "role <name> still has <n> device(s); take them out first", or "role <name> is named by
             <n> reservation(s): <ip> (<name>), …; take the role off them first (…--role none)"; ldb.LdbError
             ERR_NO_SUCH_OBJECT,
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "remove_role")."""
    found = samdb.search(base=sites_dn(samdb), scope=ldb.SCOPE_SUBTREE,
                         expression=f"(&(objectClass=fabricRole)(cn={ldb.binary_encode(name)}))", attrs=["dn"])
    if not found:
        raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT, f"no role {name}")
    members = samdb.search(base=devices_dn(samdb, site), scope=ldb.SCOPE_ONELEVEL,
                           expression=f"(fabricRoleName={ldb.binary_encode(name)})", attrs=["cn"])
    if members:
        raise ValueError(f"role {name} still has {len(members)} device(s); take them out first")
    try:
        reserved = samdb.search(base=f"OU=networks,{site_dn(samdb, site)}", scope=ldb.SCOPE_SUBTREE,
                                expression=f"(&(objectClass=fabricAddress)(fabricRoleName={ldb.binary_encode(name)}))",
                                attrs=["fabricIp", "fabricHostName"])
    except ldb.LdbError as exc:
        if exc.args[0] != ldb.ERR_NO_SUCH_OBJECT:       # a site with no OU=networks has no reservations
            raise
        reserved = []
    if reserved:
        named = sorted(str(m.get("fabricIp", idx=0)) + (f" ({m.get('fabricHostName', idx=0)})"
                                                        if m.get("fabricHostName") else "") for m in reserved)
        raise ValueError(f"role {name} is named by {len(reserved)} reservation(s): {', '.join(named)}; take the role "
                         "off them first (fabricctl ipam address set <ip> --role none)")
    samdb.delete(str(found[0].dn))
    return {"name": name}
