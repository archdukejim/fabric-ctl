"""Where an account lives and where its roles reach (decision 2.1.9.24, manual 1.6.3.18.8): an account may hold a role
only if it lives at that role's site or above. The helpers grant_site_role, add_group_member, move_person,
protect_privileged_people, list_site_roles and converge share."""
import ldb

import paths

IN_CHAIN = "1.2.840.113556.1.4.1941"            # LDAP_MATCHING_RULE_IN_CHAIN: nested membership counts
# the domain's own administrators, by RID under the domain SID (Domain Admins, Schema Admins, Enterprise Admins)
ADMIN_RIDS = (512, 518, 519)
BUILTIN_ADMINS = "S-1-5-32-544"                 # BUILTIN\Administrators
# a group in any site's OU=groups whose name ends so holds a role (2.1.9.13, 2.1.9.21)
ROLE_SUFFIXES = ("-admins", "-operators", "-helpdesk", "-auditors")


def site_of(samdb, dn):
    """Purpose: the site an object lives in: the nearest site OU (fabricSiteInfo) above it.
    Inputs:  samdb — SamDB; dn — str.
    Returns: str, the site's name; "" for an object outside every site (the domain's own, e.g. CN=Users).
    Fails:   ldb.LdbError from a search.
    Feeds:   role_sites, misplaced, move_person, grant_site_role, add_group_member."""
    parts = dn.split(",")
    for i in range(1, len(parts)):
        if not parts[i].upper().startswith("OU="):
            continue
        try:
            res = samdb.search(base=",".join(parts[i:]), scope=ldb.SCOPE_BASE, attrs=["ou"],
                               expression="(objectClass=fabricSiteInfo)")
        except ldb.LdbError as e:
            if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
                raise
            continue
        if res:
            return str(res[0]["ou"][0])
    return ""


def top_site(samdb):
    """Purpose: the top site (its OU directly in OU=sites), where Central IT lives.
    Inputs:  samdb — SamDB.
    Returns: str, its name ("" before the layout exists).
    Fails:   ldb.LdbError from the search.
    Feeds:   role_sites."""
    res = samdb.search(base=paths.sites_dn(samdb), scope=ldb.SCOPE_ONELEVEL, attrs=["ou"],
                       expression="(objectClass=fabricSiteInfo)")
    return str(res[0]["ou"][0]) if res else ""


def lineage(samdb, site):
    """Purpose: a site and every site above it, nearest first: where an account holding a role at the site may live.
    Inputs:  samdb — SamDB; site — str.
    Returns: list of str.
    Fails:   as paths.ancestors.
    Feeds:   misplaced, placement_refusal, move_person."""
    return [site] + paths.ancestors(samdb, site)


def role_group_dns(samdb, privileged):
    """Purpose: the DNs of every group whose members hold a role somewhere: the named fabric groups, the domain's own
             administrators, and every site's admin and role groups.
    Inputs:  samdb — SamDB; privileged — list of group names (the organisation's fabric groups).
    Returns: list of str DNs.
    Fails:   ldb.LdbError from a search.
    Feeds:   role_sites, protect_privileged_people."""
    base, sid = str(samdb.domain_dn()), samdb.get_domain_sid()
    named = "".join(f"(sAMAccountName={ldb.binary_encode(n)})" for n in privileged)
    sids = "".join(f"(objectSid={sid}-{rid})" for rid in ADMIN_RIDS) + f"(objectSid={BUILTIN_ADMINS})"
    found = [str(m.dn) for m in samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                                             expression=f"(&(objectClass=group)(|{named}{sids}))")]
    roles = "".join(f"(cn=*{s})" for s in ROLE_SUFFIXES)
    found += [str(m.dn) for m in samdb.search(base=paths.sites_dn(samdb), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                                              expression=f"(&(objectClass=group)(|{roles}))")]
    return sorted(set(found))


def role_sites(samdb, dn, privileged, roles=None):
    """Purpose: the sites at which membership of an object (a person, or a group) gives a role: each role group it is
             in, nested too (or is, for a group), at the site that group lives in; the organisation's fabric groups and
             the domain's administrators at the top site.
    Inputs:  samdb — SamDB; dn — the person's or group's DN; privileged — list of str; roles — role_group_dns' list
             (default: read it).
    Returns: {site: [role group names]}.
    Fails:   ldb.LdbError from a search.
    Feeds:   placement_refusal, misplaced."""
    roles = {r.lower() for r in (roles if roles is not None else role_group_dns(samdb, privileged))}
    held = [str(m.dn) for m in samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                                            expression=f"(&(objectClass=group)(member:{IN_CHAIN}:="
                                                       f"{ldb.binary_encode(dn)}))")] + [dn]
    out, top = {}, None
    for group in held:
        if group.lower() not in roles:
            continue
        where = site_of(samdb, group)
        if not where:
            top = top if top is not None else top_site(samdb)
            where = top
        out.setdefault(where, []).append(group.split(",", 1)[0].split("=", 1)[1])
    return out


def placement_refusal(samdb, person_dn, sites):
    """Purpose: why a person may not hold roles at these sites, or "" when they may: they must live at each site or
             above it (2.1.9.24).
    Inputs:  samdb — SamDB; person_dn — str; sites — iterable of site names the person would hold a role at.
    Returns: str, the refusal naming where the account must live and how to move it; "" when allowed.
    Fails:   ldb.LdbError from a search.
    Feeds:   grant_site_role, add_group_member, move_person."""
    lives = site_of(samdb, person_dn)
    if not lives:
        return ""                       # the domain's own accounts live above every site
    uid = person_dn.split(",", 1)[0].split("=", 1)[1]
    for site in sorted(set(sites)):
        if lives not in lineage(samdb, site):
            return (f"{uid} lives at {lives}, but a role at {site} may be held only by an account living at {site} or "
                    f"a site above it ({', '.join(lineage(samdb, site))}) (2.1.9.24): move it first, from a site above "
                    f"both, with fabricctl people move {uid} --site {site}")
    return ""


def misplaced(samdb, site, privileged):
    """Purpose: the people of a site's OU=people who hold a role at a site above theirs (2.1.9.24): placed before the
             rule, or by hand. Reported, never moved.
    Inputs:  samdb — SamDB; site — str; privileged — list of str.
    Returns: list of {"uid", "lives", "holds": {site: [groups]}} for those whose roles reach above their site.
    Fails:   ldb.LdbError from a search.
    Feeds:   protect_privileged_people, list_site_roles, converge."""
    people = f"OU=people,{paths.site_dn(samdb, site)}"
    roles = role_group_dns(samdb, privileged)
    out = []
    for m in samdb.search(base=people, scope=ldb.SCOPE_SUBTREE, attrs=["sAMAccountName"],
                          expression="(&(objectCategory=person)(objectClass=user))"):
        lives = site_of(samdb, str(m.dn))
        holds = {s: g for s, g in role_sites(samdb, str(m.dn), privileged, roles).items()
                 if lives not in lineage(samdb, s)}
        if holds:
            out.append({"uid": str(m.get("sAMAccountName", [""])[0]), "dn": str(m.dn), "lives": lives,
                        "holds": holds})
    return out
