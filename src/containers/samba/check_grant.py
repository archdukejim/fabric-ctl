from grant_members import TOP_RIDS, find_group
from grant_names import (ALL_SITES, FIELDS, GPO_RIGHTS, KINDS, MACHINE_RIGHTS, NAME_RE, NETWORK_RIGHTS, PEOPLE_RIGHTS,
                         RESERVED, SIGNIN_RIGHTS, SUDO_ALL, gpo_rights)
from group_names import DC_HOSTS, DIRECTORY_ADMINS

DOMAIN_USERS_RID = 513
COMPUTED = ("grant-", "access-")              # fabric's computed groups (OU=fabric): never named by a grant


def _list(grant, key, allowed=None):
    """Purpose: one of a grant's list fields, checked: a list of text, no repeats, each of `allowed` when given.
    Inputs:  grant — dict; key — str; allowed — tuple of str, or None (any text).
    Returns: list of str, in the order given.
    Fails:   ValueError naming the field and what is wrong.
    Feeds:   check_grant."""
    value = grant.get(key, FIELDS[key])
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        raise ValueError(f"{key}: a list of names")
    value = [x.strip() for x in value]
    if len(set(value)) != len(value):
        raise ValueError(f"{key}: a name given twice")
    bad = [x for x in value if allowed is not None and x not in allowed]
    if bad:
        raise ValueError(f"{key}: {', '.join(bad)} is not one of {', '.join(allowed)}")
    return value


def _group_refused(samdb, name, field):
    """Purpose: why a grant may not name a group in its who or where: it is not a group of the domain, it is one of
             the tiers' (2.1.6.66: the Directory Administrators, AD's top tier; the DC hosts, 1.6.13.6), or one of
             fabric's computed groups.
    Inputs:  samdb — SamDB; name — str; field — "who" or "where".
    Returns: str (why), or None when it may be named.
    Fails:   ldb.LdbError from a search.
    Feeds:   check_grant."""
    if name.lower().startswith(COMPUTED):
        return f"{field}: {name} is one of fabric's computed groups (manual 1.6.13.4): name the groups it is made from"
    found = find_group(samdb, name)
    if found is None:
        return f"{field}: no group {name} in the domain"
    if name.lower() == DC_HOSTS:
        return (f"{field}: no grant reaches the hosts that run a domain controller (manual 1.6.13.6): only "
                "fabric-admin and the host's local-admin sign in there")
    sid = found[1]
    top = {f"{samdb.get_domain_sid()}-{rid}" for rid in TOP_RIDS} | {"S-1-5-32-544"}
    if name.lower() == DIRECTORY_ADMINS or sid in top:
        return (f"{field}: {name} is one of the tiers' groups (2.1.6.66): only the tier above manages its members, "
                "and no grant reaches them")
    return None


def _everyone(samdb, name):
    """Purpose: whether a group means every person, or every person of a site: AD's Domain Users (fabric's `users`)
             or a `site-<name>` group.
    Inputs:  samdb — SamDB; name — str (a group of the domain).
    Returns: bool.
    Fails:   ldb.LdbError from a search.
    Feeds:   check_grant."""
    found = find_group(samdb, name)
    return name.lower().startswith("site-") or (found is not None
                                                and found[1] == f"{samdb.get_domain_sid()}-{DOMAIN_USERS_RID}")


def _sites(samdb, sites, networks):
    """Purpose: a grant's sites checked (1.6.13.12, 2.1.10.36): only with networks rights, and then at least one;
             `all` alone, or sites of the domain (each has its group `site-<name>`).
    Inputs:  samdb — SamDB; sites — the grant's sites, as _list gave them; networks — its networks rights.
    Returns: None.
    Fails:   ValueError with why; ldb.LdbError from a search.
    Feeds:   check_grant."""
    if not networks:
        if sites:
            raise ValueError("sites: only for networks rights (manual 1.6.13.12)")
        return
    if not sites:
        raise ValueError("sites: a grant with networks rights names at least one site, or all (manual 1.6.13.12)")
    if ALL_SITES in sites:
        if len(sites) > 1:
            raise ValueError("sites: all (every site) alone, or a list of sites")
        return
    for name in sites:
        if find_group(samdb, f"site-{name}") is None:
            raise ValueError(f"sites: no site {name} in the domain")


def check_grant(samdb, grant):
    """Purpose: a grant as it may be stored (manual 1.6.13.4, 2.1.6.73, 2.1.6.77), or why not: its name (2-40
             characters, a-z 0-9 -, starting with a letter; not a word of the CLI); allowing or restricting; who and
             where each at least one group of the domain, never a tier's group, the DC hosts or a computed group; the
             rights from their categories (people, machines, sign-in, sudo, local administrator), at least one; a
             restricting grant only the rights a set's GPO carries (sign-in, local administrator); sudo either every
             command (ALL, alone) or absolute paths, and every command refused when the who means every person (Domain
             Users, a whole site); networks rights (plan, options, scan) with the sites they hold at (`all`, or sites
             of the domain), a grant of networks rights alone needing no where (1.6.13.12, 2.1.10.36).
    Inputs:  samdb — SamDB; grant — dict: name and any of FIELDS' keys (missing ones empty).
    Returns: dict, the grant with every field, normalised.
    Fails:   ValueError with why (the message is shown to the person asking).
    Feeds:   grants_tool (add, set), ship_grants."""
    name = grant.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name) or name in RESERVED:
        raise ValueError("a grant's name: 2-40 characters, a-z 0-9 -, starting with a letter (not explain or sync)")
    kind = grant.get("kind", "allow")
    if kind not in KINDS:
        raise ValueError("kind: allow or restrict")
    description = grant.get("description", "")
    if not isinstance(description, str) or len(description) > 200 or "\n" in description:
        raise ValueError("description: one line of text, at most 200 characters")
    out = {"name": name, "kind": kind, "description": description.strip(),
           "who": _list(grant, "who"), "where": _list(grant, "where"),
           "people": _list(grant, "people", PEOPLE_RIGHTS), "machines": _list(grant, "machines", MACHINE_RIGHTS),
           "signin": _list(grant, "signin", SIGNIN_RIGHTS), "sudo": _list(grant, "sudo"),
           "networks": _list(grant, "networks", NETWORK_RIGHTS), "sites": _list(grant, "sites")}
    local_admin = grant.get("local_admin", False)
    if not isinstance(local_admin, bool):
        raise ValueError("local_admin: true or false")
    out["local_admin"] = local_admin
    others = out["people"] or out["machines"] or out["signin"] or out["sudo"] or local_admin
    for field in ("who", "where"):
        if field == "where" and not out[field] and out["networks"] and not others:
            continue                          # networks rights alone: they hold at sites, not on groups' members
        if not out[field]:
            raise ValueError(f"{field}: at least one group (manual 1.6.13.4)")
        for g in out[field]:
            why = _group_refused(samdb, g, field)
            if why:
                raise ValueError(why)
    _sites(samdb, out["sites"], out["networks"])
    sudo = out["sudo"]
    if SUDO_ALL in sudo and len(sudo) > 1:
        raise ValueError("sudo: ALL (every command) alone, or a list of commands")
    if any(c != SUDO_ALL and not c.startswith("/") for c in sudo):
        raise ValueError("sudo: each command an absolute path (with its arguments), or ALL")
    if kind == "restrict":
        if out["people"] or out["machines"] or sudo or out["networks"]:
            raise ValueError("a restricting grant narrows sign-in or local administrator only (" + ", ".join(GPO_RIGHTS)
                             + "): the rights a set of machines' GPO carries (manual 1.6.13.4)")
        if not gpo_rights(out):
            raise ValueError("a restricting grant names the right it narrows: sign-in (keyboard, remote) or local "
                             "administrator")
    elif not (others or out["networks"]):
        raise ValueError("a grant gives at least one right")
    if SUDO_ALL in sudo and all(_everyone(samdb, g) for g in out["who"]):
        raise ValueError("sudo of every command for every person (or a whole site) is refused (manual 1.6.13.4): "
                         "name the groups who need it, or the commands they need")
    return out
