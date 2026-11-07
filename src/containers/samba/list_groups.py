
from group_kind import group_kind
from directory_scope import find_groups


def list_groups(samdb, lp, site, bundles=()):
    """Purpose: the domain's groups in OU=groups (manual 1.6.12.5): each with its kind (fabric's, an admin's own, a
             machine group, ...; group_kind), its member count and description; the grants' computed groups (OU=fabric)
             are listed as such.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); bundles — the groups
             carrying a fabric role bundle.
    Returns: {"groups": [{"name", "kind", "members" (count), "description"}]}, by name.
    Fails:   ldb.LdbError from a search.
    Feeds:   directory_ops (op "list_groups")."""
    out = []
    for g in find_groups(samdb, attrs=["sAMAccountName", "member", "description"]):
        name = str(g["sAMAccountName"][0])
        out.append({"name": name, "kind": group_kind(samdb, name, bundles)["kind"],
                    "members": len(g.get("member", [])), "description": str(g.get("description", [""])[0])})
    return {"groups": sorted(out, key=lambda x: x["name"].lower())}
