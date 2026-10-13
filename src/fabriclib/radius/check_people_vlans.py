from fabriclib.common.errors import ValidationError


def check_people_vlans(people, plan):
    """Purpose: the VLANs the groups mapped for password logins name (radius_people, manual 1.11.1.1) are VLANs of this
             site's address plan, the same rule as a device role's (1.11.1.8; decision 2.1.11.9): when the plan has
             VLANs, each mapping's must be one of them; a plan without VLANs, or no plan kept, accepts any number.
    Inputs:  people — radius_people's mappings ([{"group", "vlan" (int, str or None), …}], or None); plan — this
             site's plan (site_plan's shape: "site", "vlans"), or None when none was kept.
    Returns: None.
    Fails:   ValidationError "radius_people: <group> names VLAN <n>, … not in <site>'s address plan (its VLANs: …):
             add them with `fabricctl ipam vlan add` first, or map the groups to one of them" (every such group named).
    Feeds:   deploy_freeradius (apply)."""
    ids = [int(x["id"]) for x in (plan or {}).get("vlans") or []]
    if not ids:
        return
    bad = [(str(m.get("group")), int(m["vlan"])) for m in people or []
           if m.get("vlan") not in (None, "", 0, "0") and int(m["vlan"]) not in ids]
    if not bad:
        return
    names = ", ".join(f"{x['id']} ({x['name']})" if x.get("name") else str(x["id"]) for x in plan["vlans"])
    raise ValidationError("radius_people: " + ", ".join(f"{g} names VLAN {n}" for g, n in bad)
                          + f", not in {plan.get('site') or 'this site'}'s address plan (its VLANs: {names}): add "
                          "them with `fabricctl ipam vlan add` first, or map the groups to one of them")
