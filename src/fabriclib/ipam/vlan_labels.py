def vlan_labels(plan):
    """Purpose: how the address plan names each VLAN, for pages that show a bare VLAN number (a device role's VLAN,
             manual 1.11.1.8): "iot, 10.1.20.0/24" (its name and its subnets).
    Inputs:  plan — a site's plan (site_plan's shape: "vlans", "subnets"), or None (no plan kept).
    Returns: dict {str(VLAN id): label}; {} without a plan.
    Fails:   never.
    Feeds:   directory.device_overview (the Roles table)."""
    if not plan:
        return {}
    out = {}
    for vlan in plan.get("vlans") or []:
        cidrs = [s["cidr"] for s in plan.get("subnets") or [] if s.get("vlan") == vlan["id"] and s.get("cidr")]
        out[str(vlan["id"])] = ", ".join([vlan.get("name") or ""] * bool(vlan.get("name")) + cidrs)
    return out
