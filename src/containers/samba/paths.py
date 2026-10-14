import ldb

_found = {}


def site_dn(samdb, site):
    """Purpose: a site's OU, wherever it sits: sites nest, each in its parent's OU (2.1.6.20, manual 1.6.3.4), so the OU
             is found by its mark (the fabricSiteInfo class ensure_layout gives it) and its name, never built from them.
    Inputs:  samdb — SamDB; site — str.
    Returns: str, e.g. "OU=lab,OU=lan,OU=sites,<domain>".
    Fails:   LookupError when no site OU has that name; ldb.LdbError from the search.
    Feeds:   the directory operations and converge's parts."""
    if site not in _found:
        res = samdb.search(base=sites_dn(samdb), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                           expression=f"(&(objectClass=fabricSiteInfo)(ou={ldb.binary_encode(site)}))")
        if len(res) != 1:
            raise LookupError(f"site {site}: {'no' if not res else 'more than one'} site OU of that name")
        _found[site] = str(res[0].dn)
    return _found[site]


def forget():
    """Purpose: drop every site OU found so far: after a site moved, its DN and those of the sites below it changed.
    Inputs:  none.
    Returns: None.
    Fails:   never.
    Feeds:   ensure_layout (a move)."""
    _found.clear()


def organisation_dn(samdb):
    """Purpose: the organisation's OU, in the root site's OU (manual 1.6.3.4).
    Inputs:  samdb — SamDB.
    Returns: str "OU=organisation,OU=<root>,OU=sites,<domain>".
    Fails:   LookupError when there is none yet; ldb.LdbError from the search.
    Feeds:   ensure_groups, save_role, ensure_site_acl."""
    res = samdb.search(base=sites_dn(samdb), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                       expression="(&(objectClass=organizationalUnit)(ou=organisation))")
    if len(res) != 1:
        raise LookupError("the organisation's OU: " + ("none yet" if not res else "more than one"))
    return str(res[0].dn)


def ancestors(samdb, site):
    """Purpose: the sites above a site, nearest first (its OU's enclosing site OUs, 2.1.6.20).
    Inputs:  samdb — SamDB; site — str.
    Returns: list of str, site names ([] for the root).
    Fails:   as site_dn.
    Feeds:   ensure_site_acl (the parents' service-account deny), the sudo rule and log-on lists."""
    out = []
    dn = site_dn(samdb, site).split(",", 1)[1]
    top = sites_dn(samdb).lower()
    while dn.lower() != top and dn.upper().startswith("OU="):
        out.append(dn.split(",", 1)[0].split("=", 1)[1])
        dn = dn.split(",", 1)[1]
    return out


def below(samdb, site):
    """Purpose: the sites nested below a site, at any depth (their OUs inside its OU, 2.1.6.20): what a site may grant
             roles at (2.1.9.21) and the only other sites it lists (2.1.9.22).
    Inputs:  samdb — SamDB; site — str.
    Returns: list of str, site names, sorted ([] when none).
    Fails:   as site_dn; ldb.LdbError from the search.
    Feeds:   converge (narrow_site_admins), list_site_roles, grant_site_role."""
    top = site_dn(samdb, site)
    res = samdb.search(base=top, scope=ldb.SCOPE_SUBTREE, attrs=["ou"], expression="(objectClass=fabricSiteInfo)")
    return sorted(str(m["ou"][0]) for m in res if str(m.dn).lower() != top.lower())


def relative(samdb, dn):
    """Purpose: a DN without the domain's own part, as samba's newuser and newcomputer take their container.
    Inputs:  samdb — SamDB; dn — str, inside the domain.
    Returns: str, e.g. "OU=people,OU=lab,OU=lan,OU=sites".
    Fails:   ValueError when dn is not inside the domain.
    Feeds:   create_person, create_machine, ensure_service_accounts."""
    suffix = "," + str(samdb.domain_dn())
    if not dn.lower().endswith(suffix.lower()):
        raise ValueError(f"{dn}: not inside {suffix[1:]}")
    return dn[:-len(suffix)]


def devices_dn(samdb, site):
    """Purpose: a site's devices (manual 1.6.3.4).
    Inputs:  samdb — SamDB; site — str.
    Returns: str.
    Fails:   as site_dn.
    Feeds:   the device operations."""
    return f"OU=devices,{site_dn(samdb, site)}"


def sites_dn(samdb):
    """Purpose: everything fabric manages (2.1.6.12).
    Inputs:  samdb — SamDB.
    Returns: str "OU=sites,<domain>".
    Fails:   never.
    Feeds:   the directory operations (searches across sites)."""
    return f"OU=sites,{samdb.domain_dn()}"
