import ldb

import paths

# every site's OU holds these (manual 1.6.3.4); the root site's also holds OU=organisation
SITE_OUS = ("people", "groups", "machines", "devices", "device-roles", "networks", "sudoers", "service-accounts")
ORGANISATION_OUS = ("groups", "device-roles", "sudoers")
# each site's OU=machines holds one OU per OS family: a machine is placed in its own once (2.1.6.36, 1.6.11.5)
MACHINE_OUS = ("linux", "windows")
# AD's well-known containers for new users and computers (redirusr, redircmp)
WELL_KNOWN = {"A9D1CA15768811D1ADED00C04FD8D5CD": "people", "AA312825768811D1ADED00C04FD8D5CD": "machines"}


def _ensure_ou(samdb, dn):
    """Purpose: an organisational unit, created when missing.
    Inputs:  samdb — SamDB; dn — str.
    Returns: True if it was created.
    Fails:   ldb.LdbError other than "already exists" (a missing parent, refused).
    Feeds:   ensure_layout."""
    try:
        samdb.add({"dn": dn, "objectClass": "organizationalUnit"})
        return True
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_ENTRY_ALREADY_EXISTS:
            return False
        raise


def ensure_layout(samdb, site, root, parent=""):
    """Purpose: everything fabric manages under OU=sites, one OU per site, each site's in its parent's (2.1.6.12,
             2.1.6.20, manual 1.6.3.4), marked as a site OU (fabricSiteInfo) as it is made so it is found wherever it
             sits; and AD's default containers for new users and computers pointed at the root site's OU=people and
             OU=machines (so nothing Windows' own tools create lands outside OU=sites).
    Inputs:  samdb — SamDB; site — str, this site's name; root — bool, this is the root site (its OU is directly
             under OU=sites, it also holds OU=organisation, and the defaults point at it); parent — str, a site's
             parent site (whose OU must exist: the parent converges first).
    Returns: list of str, what was created or changed.
    Fails:   ValueError for a site with neither root nor parent; LookupError when the parent's OU is missing;
             ldb.LdbError from an addition or modification AD refuses.
    Feeds:   converge.
    Notes:   a site OU that sits under another parent than `parent` is moved under it, with everything in it
             (re-parenting, manual 1.9.8.14): AD keeps every object's SID and GUID, and the access its new parents
             give is inherited at once."""
    base = str(samdb.domain_dn())
    done = []
    if _ensure_ou(samdb, f"OU=sites,{base}"):
        done.append(f"OU=sites,{base}")
    try:
        site_dn = paths.site_dn(samdb, site)
        if parent and not root:
            above = paths.site_dn(samdb, parent)
            if site_dn.split(",", 1)[1].lower() != above.lower():
                if above.lower().endswith("," + site_dn.lower()):
                    raise ValueError(f"site {site}: {parent} sits below it, so it cannot become its parent")
                moved = f"OU={site},{above}"
                samdb.rename(site_dn, moved)
                paths.forget()
                done.append(f"site {site} moved: {site_dn} -> {moved}")
                site_dn = moved
    except LookupError:
        if root:
            site_dn = f"OU={site},OU=sites,{base}"
        elif parent:
            site_dn = f"OU={site},{paths.site_dn(samdb, parent)}"
        else:
            raise ValueError(f"site {site}: not the root and no parent: its OU has nowhere to go")
        if _ensure_ou(samdb, site_dn):
            done.append(site_dn)
        # the mark first, on its own (the id block comes with ensure_site_info): the OU is found by it from now on
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": site_dn, "objectClass": "fabricSiteInfo"}, ldb.FLAG_MOD_ADD))
    wanted = [f"OU={ou},{site_dn}" for ou in SITE_OUS] + [f"OU={ou},OU=machines,{site_dn}" for ou in MACHINE_OUS]
    if root:
        wanted += [f"OU=organisation,{site_dn}"] + [f"OU={ou},OU=organisation,{site_dn}" for ou in ORGANISATION_OUS]
    done += [dn for dn in wanted if _ensure_ou(samdb, dn)]
    if root:
        res = samdb.search(base=base, scope=ldb.SCOPE_BASE, attrs=["wellKnownObjects"])
        for value in [str(x) for x in res[0].get("wellKnownObjects", [])]:
            guid = value.split(":")[2]
            if guid not in WELL_KNOWN:
                continue
            target = f"OU={WELL_KNOWN[guid]},{site_dn}"
            current = value.split(":", 3)[3]
            if current.lower() == target.lower():
                continue
            # the value is replaced in one modify, as Windows' redirusr/redircmp do
            samdb.modify_ldif(f"dn: {base}\nchangetype: modify\ndelete: wellKnownObjects\nwellKnownObjects: {value}\n"
                              f"-\nadd: wellKnownObjects\nwellKnownObjects: B:32:{guid}:{target}\n")
            done.append(f"new {WELL_KNOWN[guid]} go to {target}")
    return done
