import time


def site_plan(read, site):
    """Purpose: one site's plan out of read_plan's answer (manual 1.10.4.32, 1.10.4.33), with its number, as fabric
             keeps and renders it.
    Inputs:  read — read_plan's result ({"sites", "plans", "option_sets", "options"}); site — str.
    Returns: {"site", "block" (int or None), "rules" (the site's access rules as kept, 1.10.4.48.4), "rules_kept"
             (bool: any are kept), "vlans", "subnets", "networks", "domain_options" (the domain's option set,
             or None before the root's convergence made it), "site_options" (the site's, from its record: {"options",
             "option_defs", "client_classes"}), "read" (local time it was read)}; empty lists for a site with nothing
             in its plan. Who may change it is the grants' (1.6.13.12), checked by fabric-agent, not kept here.
    Fails:   never.
    Feeds:   the plan's functions (1.10.4.41, area 4); load_address_plan, poll_plan (Kea and DNS from it, area 5)."""
    plan = (read.get("plans") or {}).get(site) or {}
    record = next((s for s in read.get("sites") or [] if s["name"] == site), {})
    block = record.get("block")
    sets = read.get("option_sets") or {}
    return {"site": site, "block": block, "rules": record.get("rules") or [],
            "rules_kept": bool(record.get("rules_kept")), "vlans": plan.get("vlans") or [],
            "subnets": plan.get("subnets") or [],
            "networks": plan.get("networks") or [], "domain_options": sets.get("domain"),
            "site_options": sets.get(site) or {"options": [], "option_defs": [], "client_classes": []},
            "read": time.strftime("%Y-%m-%d %H:%M:%S")}
