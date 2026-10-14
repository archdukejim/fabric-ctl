import time


def site_plan(read, site):
    """Purpose: one site's plan out of read_plan's answer, with its number, as fabric keeps and renders it.
    Inputs:  read — read_plan's result; site — str.
    Returns: {"site", "block" (int or None), "vlans", "subnets", "networks", "org_options" (the organisation's option
             set or None), "site_options" (the site's: {"options", "option_defs", "client_classes"}), "org_editors"
             (the sites the top lets edit the organisation's, 2.1.10.23), "local_scan" (whether the site's own admins
             may scan, {"allowed", "set_by", "top", "above"}, 2.1.10.30; {} from a DC without it), "read" (local time
             it was read)}; empty lists for a site with nothing in its plan.
    Fails:   never.
    Feeds:   load_address_plan, move_subnets_to_plan, common/edit_plan, run_ipam_command (show, export)."""
    plan = (read.get("plans") or {}).get(site) or {}
    block = next((s.get("block") for s in read.get("sites") or [] if s["name"] == site), None)
    sets = read.get("option_sets") or {}
    return {"site": site, "block": block, "vlans": plan.get("vlans") or [], "subnets": plan.get("subnets") or [],
            "networks": plan.get("networks") or [], "org_options": sets.get("org"),
            "site_options": sets.get(site) or {"options": [], "option_defs": [], "client_classes": []},
            "org_editors": read.get("org_editors") or [],
            "local_scan": (read.get("local_scan") or {}).get(site) or {},
            "read": time.strftime("%Y-%m-%d %H:%M:%S")}
