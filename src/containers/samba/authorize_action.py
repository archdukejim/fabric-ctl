"""fabric-agent's check of who may do what (manual 1.6.12.2, 1.6.12.11, 1.6.13.4; 2.1.6.66 to 2.1.6.68, 2.1.6.73): the
tiers, the grants' people and machines rights, and a group's two levels, decided from the directory as it is."""
import ldb

import paths
from grant_members import excluded, group_members, reach, tiers
from grant_names import MACHINE_RIGHTS, PEOPLE_RIGHTS
from grant_store import read_grants
from group_kind import group_kind
from group_names import DIRECTORY_ADMINS
from group_store import read_managers

RANK = {"delegated": 1, "directory": 2, "enterprise": 3}
# an action on one person or machine -> (the grant's category, the right in it)
PEOPLE = {"people:edit": "edit", "people:reset": "reset", "people:unlock": "unlock", "people:disable": "disable",
          "people:remove": "add", "people:add": "add"}
MACHINES = {"machines:add": "add", "machines:move": "move", "machines:disable": "disable",
            "machines:remove": "remove", "machines:groups": "groups"}
DEFAULT_GROUPS = {"people": "domain users", "machines": "domain computers"}   # every new account's primary group
TOP = ("in AD's top tier (the Enterprise Admin, break glass): managed only on the DC's host (manual 1.6.12.16.5), "
       "never through fabric-agent")
OWN = "one of fabric's own accounts: managed by fabric (manual 1.6.12.2)"
DIRECTORY = ("a Directory Administrator: only the Enterprise Admin (fabric-admin, or root on a fabric host) manages "
             "them (2.1.6.66, 2.1.6.68)")


def _account(samdb, name, computer=False):
    """Purpose: an account by its name: a person's (anywhere) or a computer's.
    Inputs:  samdb — SamDB; name — user name, or a computer's short name; computer — bool.
    Returns: ldb.Message (dn, memberOf), or None.
    Fails:   ldb.LdbError from the search.
    Feeds:   authorize_action."""
    account = name.rstrip("$") + "$" if computer else name
    kind = "(objectClass=computer)" if computer else "(&(objectClass=user)(!(objectClass=computer)))"
    found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=["memberOf"],
                         expression=f"(&{kind}(sAMAccountName={ldb.binary_encode(account)}))")
    return found[0] if found else None


def _caller_tier(samdb, t, caller):
    """Purpose: the caller's tier: root on a fabric host acts for the Enterprise Admin (as for the tiers' password
             policies and the local accounts, 1.6.12.16); a person in AD's top tier is the Enterprise Admin's tier; a
             Directory Administrator theirs; anyone else is delegated.
    Inputs:  samdb — SamDB; t — tiers(); caller — user name, or None (root).
    Returns: (tier str, the caller's dn or None).
    Fails:   ValueError for a caller who is not a person of the domain, or one of fabric's own accounts.
    Feeds:   authorize_action."""
    if caller is None:
        return "enterprise", None
    found = _account(samdb, caller)
    if found is None:
        raise ValueError(f"you ({caller}) are not a person of the domain")
    dn = str(found.dn).lower()
    if dn in t["fabric_accounts"]:
        raise ValueError(f"{caller} is one of fabric's own accounts: it acts for no one")
    if dn in t["ad_top"]:
        return "enterprise", dn
    return ("directory" if dn in t["directory_admins"] else "delegated"), dn


def _grants_giving(samdb, category, right, caller_dn, target_dn=None, target_groups=None):
    """Purpose: the allowing grants that give the caller a right on an account: the caller in all the grant's who,
             and the account in all its where (an existing one, by membership; a new one, by the groups it will be
             made in).
    Inputs:  samdb — SamDB; category — "people" or "machines"; right — one of its rights; caller_dn — str; target_dn —
             an existing account's dn (lower case), or None; target_groups — a new account's groups (lower case).
    Returns: list of grant names.
    Fails:   ldb.LdbError from a search.
    Feeds:   authorize_action."""
    out, cache, by = excluded(samdb), {}, []
    for g in read_grants(samdb):
        if g["kind"] != "allow" or right not in (g.get(category) or []):
            continue
        r = reach(samdb, g, out, cache)
        if caller_dn not in r["who"]:
            continue
        if target_dn is not None:
            where = r["where_people"] if category == "people" else r["where_computers"]
            if target_dn in where:
                by.append(g["name"])
        elif {w.lower() for w in g["where"]} <= set(target_groups) | {DEFAULT_GROUPS[category]}:
            by.append(g["name"])
    return by


def _in_group(samdb, dn, group):
    """Purpose: whether an account is in a group, nesting followed (its primary group too).
    Inputs:  samdb — SamDB; dn — str (lower case); group — the group's name.
    Returns: bool.
    Fails:   ldb.LdbError.
    Feeds:   authorize_action."""
    m = group_members(samdb, group)
    return dn in m["people"] or dn in m["computers"]


def _members_action(samdb, t, tier, caller, caller_dn, target, bundles):
    """Purpose: whether the caller may put a member into a group or take one out (2.1.6.67, level 2): the tier above
             the group, or one of its managers within their controls; never AD's own groups, the computed ones or
             those fabric fills; the member a person or a group, never one the caller's tier is below.
    Inputs:  samdb, t, tier, caller, caller_dn — as authorize_action has them; target — {"name": group, "member": name,
             "add": bool}; bundles — the groups carrying a role bundle.
    Returns: str, by what it is allowed ("tier" or "manager").
    Fails:   ValueError saying why it is refused.
    Feeds:   authorize_action."""
    g = group_kind(samdb, str(target.get("name", "")), bundles)
    if g["kind"] == "ad":
        raise ValueError(f"{g['name']} is one of AD's own groups: fabric leaves it as AD has it (manual 1.6.12.2)")
    if g["kind"] == "computed":
        raise ValueError(f"{g['name']} is computed for the grants: written only by fabric (manual 1.6.13.4)")
    if g["kind"] == "filled" or g["name"].lower() == "dc-hosts":
        raise ValueError(f"{g['name']} is filled by fabric: change a computer's type, or its host (manual 1.6.13.3)")
    if g["kind"] == "host-group":
        raise ValueError(f"{g['name']} is a machine group: change its machines on the computer (machine groups)")
    member = str(target.get("member", ""))
    person = _account(samdb, member)
    if person is not None:
        mdn = str(person.dn).lower()
        if mdn in t["ad_top"]:
            raise ValueError(f"{member} is {TOP}")
        if mdn in t["fabric_accounts"]:
            raise ValueError(f"{member} is {OWN}")
        if mdn in t["directory_admins"] and RANK[tier] < RANK["directory"]:
            raise ValueError(f"{member} is {DIRECTORY}")
    else:
        try:
            nested = group_kind(samdb, member, bundles)
        except ValueError:
            raise ValueError(f"no person or group {member} in the domain")
        if nested["kind"] in ("ad", "computed", "tier"):
            which = {"tier": "the tiers'", "ad": "AD's"}.get(nested["kind"], "the computed")
            raise ValueError(f"{member} cannot be put in another group: it is one of {which} groups")
        mdn = nested["dn"].lower()
    above = "enterprise" if g["name"].lower() == DIRECTORY_ADMINS else "directory"
    if RANK[tier] >= RANK[above]:
        return "tier"
    controls = read_managers(samdb, g["dn"])
    manager = caller is not None and any(
        m.lower() == caller.lower() or (_account(samdb, m) is None and _in_group(samdb, caller_dn, m))
        for m in controls["managers"])
    who = "the Enterprise Admin" if above == "enterprise" else "a Directory Administrator"
    if not manager:
        raise ValueError(f"you are not a manager of {g['name']}: its members are changed by its managers, or {who} "
                         f"(2.1.6.67)")
    add = bool(target.get("add"))
    if add and not controls["add"]:
        raise ValueError(f"{g['name']}'s managers may not add members (its controls: set by {who})")
    if not add and not controls["remove"]:
        raise ValueError(f"{g['name']}'s managers may not remove members (its controls: set by {who})")
    if add and controls["only_from"]:
        if person is None or not _in_group(samdb, mdn, controls["only_from"]):
            raise ValueError(f"{g['name']}'s managers may add only people already in {controls['only_from']}")
    return "manager"


def authorize_action(samdb, caller, action, target, bundles=()):
    """Purpose: whether a caller may do an action (manual 1.6.12.2, 1.6.12.11; 2.1.6.66 to 2.1.6.68, 2.1.6.73): nothing
             below a tier touches it or its members; the Directory Administrators may do everything else; anyone else
             acts on a person or a machine only through an allowing grant whose who holds them and whose where holds
             it, with that right; a group's scope and managers are the tier above it, its members that tier or its
             managers within their controls. Some accounts are nobody's through fabric-agent: AD's top tier (managed on
             the DC's host), fabric's own accounts and hosts, the DCs.
    Inputs:  samdb — SamDB (read only); caller — the signed-in person's user name, or None (root on a fabric host,
             acting for the Enterprise Admin); action — "people:edit|reset|unlock|disable|remove|add",
             "machines:add|move|disable|remove|groups", "groups:admin", "groups:members" or "domain:admin";
             target — {"name"} (a person, a machine or a group), {"groups": [names]} (people:add, machines:add: the
             groups the new account will be in), {"name", "member", "add"} (groups:members), {} (domain:admin, or
             groups:admin for a new group); bundles — the names of the groups carrying a fabric role bundle (their
             members are the Directory Administrators' to manage, 1.8.2).
    Returns: {"tier": the caller's tier, "by": "tier", "manager" or "grant <names>"}.
    Fails:   ValueError saying why it is refused (shown to the caller as it is); ldb.LdbError.
    Feeds:   grants_tool (op "authorize")."""
    t = tiers(samdb)
    tier, caller_dn = _caller_tier(samdb, t, caller)
    target = target or {}
    if action == "domain:admin" or (action == "groups:admin" and not target.get("name")):
        if RANK[tier] < RANK["directory"]:
            raise ValueError("only a Directory Administrator may do this (2.1.6.68)")
        return {"tier": tier, "by": "tier"}
    if action == "groups:admin":
        g = group_kind(samdb, str(target["name"]), bundles)
        above = "enterprise" if g["name"].lower() == DIRECTORY_ADMINS else "directory"
        if RANK[tier] < RANK[above]:
            raise ValueError(f"{g['name']}'s scope and managers are changed only by "
                             f"{'the Enterprise Admin' if above == 'enterprise' else 'a Directory Administrator'} "
                             f"(2.1.6.67)")
        return {"tier": tier, "by": "tier"}
    if action == "groups:members":
        return {"tier": tier, "by": _members_action(samdb, t, tier, caller, caller_dn, target, bundles)}
    if action in PEOPLE or action in MACHINES:
        category = "people" if action in PEOPLE else "machines"
        right = (PEOPLE if category == "people" else MACHINES)[action]
        if right not in (PEOPLE_RIGHTS if category == "people" else MACHINE_RIGHTS):
            raise ValueError(f"unknown right {right}")
        if "groups" in target:                       # a new account: by the groups it will be made in
            if RANK[tier] >= RANK["directory"]:
                return {"tier": tier, "by": "tier"}
            by = _grants_giving(samdb, category, right, caller_dn,
                                target_groups={str(x).lower() for x in target["groups"]})
            if not by:
                raise ValueError(f"no grant gives you {category} {right} where the new "
                                 f"{'person' if category == 'people' else 'machine'} would be "
                                 f"({', '.join(target['groups'])}) (manual 1.6.13.4)")
            return {"tier": tier, "by": "grant " + ", ".join(by)}
        name = str(target.get("name", ""))
        found = _account(samdb, name, computer=category == "machines")
        if found is None:
            raise ValueError(f"no {'person' if category == 'people' else 'machine'} {name} in the domain")
        dn = str(found.dn).lower()
        if category == "people":
            if dn in t["ad_top"]:
                raise ValueError(f"{name} is {TOP}")
            if dn in t["fabric_accounts"] or not dn.endswith("," + paths.folder_dn(samdb, "people").lower()):
                raise ValueError(f"{name} is {OWN}")
            if dn in t["directory_admins"]:
                if RANK[tier] < RANK["enterprise"]:
                    raise ValueError(f"{name} is {DIRECTORY}")
                return {"tier": tier, "by": "tier"}
            if RANK[tier] >= RANK["directory"]:
                return {"tier": tier, "by": "tier"}
            held = sorted({b for b in bundles if _in_group(samdb, dn, b)})
            if held:
                raise ValueError(f"{name} is in a fabric group ({', '.join(held)}): only a Directory Administrator "
                                 f"manages them (manual 1.8.2)")
        else:
            if dn in t["dc_hosts"] or not dn.endswith("," + paths.folder_dn(samdb, "machines").lower()):
                raise ValueError(f"{name} is a domain controller or a fabric host: managed by fabric (manual "
                                 f"1.6.13.6)")
            if RANK[tier] >= RANK["directory"]:
                return {"tier": tier, "by": "tier"}
        by = _grants_giving(samdb, category, right, caller_dn, target_dn=dn)
        if not by:
            raise ValueError(f"no grant gives you {category} {right} on {name} (manual 1.6.13.4)")
        return {"tier": tier, "by": "grant " + ", ".join(by)}
    raise ValueError(f"unknown action {action}")
