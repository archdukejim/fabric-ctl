import ldb

from grant_store import read_grants
from group_kind import group_kind
from group_store import read_managers
from group_uses import group_uses


def group_scope(samdb, lp, site, name, bundles=()):
    """Purpose: a group's two levels (manual 1.6.12.5, 2.1.6.67), what its page shows to everyone who sees it: level 1,
             its scope (what it grants: the grants and sudo rules that name it, the role bundle it carries) and its
             managers with their controls; level 2, its members (people, groups and computers, by name).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the group's name;
             bundles — the groups carrying a fabric role bundle.
    Returns: {"name", "kind", "description", "scope": {"grants": [{"name", "as": "who"|"where"}], "sudo": [rule names],
             "bundle": bool}, "managers": {"managers", "add", "remove", "only_from"}, "members": {"people", "groups",
             "computers"}}.
    Fails:   ValueError "no group <name> in the domain"; ldb.LdbError.
    Feeds:   directory_ops (op "group_scope")."""
    g = group_kind(samdb, name, bundles)
    res = samdb.search(base=g["dn"], scope=ldb.SCOPE_BASE, attrs=["member", "description"])[0]
    members = {"people": [], "groups": [], "computers": []}
    for m in res.get("member", []):
        found = samdb.search(base=str(m), scope=ldb.SCOPE_BASE, attrs=["objectClass", "sAMAccountName"])
        if not found:
            continue
        classes = {str(c).lower() for c in found[0].get("objectClass", [])}
        account = str(found[0].get("sAMAccountName", [""])[0])
        kind = "computers" if "computer" in classes else "groups" if "group" in classes else "people"
        members[kind].append(account.rstrip("$").lower() if kind == "computers" else account)
    low = g["name"].lower()
    grants = []
    for gr in read_grants(samdb):
        for field in ("who", "where"):
            if low in {x.lower() for x in gr.get(field, [])}:
                grants.append({"name": gr["name"], "as": field})
    return {"name": g["name"], "kind": g["kind"], "description": str(res.get("description", [""])[0]),
            "scope": {"grants": grants, "sudo": group_uses(samdb, g["name"], g["dn"])["sudo"],
                      "bundle": g["kind"] == "bundle"},
            "managers": read_managers(samdb, g["dn"]), "members": {k: sorted(v) for k, v in members.items()}}
