import time


def site_plan(read, site):
    """Purpose: one site's plan out of read_plan's answer, with its number, as fabric keeps and renders it.
    Inputs:  read — read_plan's result; site — str.
    Returns: {"site", "block" (int or None), "vlans", "subnets", "networks", "read" (local time it was read)}; empty
             lists for a site with nothing in its plan.
    Fails:   never.
    Feeds:   load_address_plan, move_subnets_to_plan, common/edit_plan, run_ipam_command (show, export)."""
    plan = (read.get("plans") or {}).get(site) or {}
    block = next((s.get("block") for s in read.get("sites") or [] if s["name"] == site), None)
    return {"site": site, "block": block, "vlans": plan.get("vlans") or [], "subnets": plan.get("subnets") or [],
            "networks": plan.get("networks") or [], "read": time.strftime("%Y-%m-%d %H:%M:%S")}
