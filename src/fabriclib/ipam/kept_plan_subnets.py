from fabriclib.ipam.common.plan_cache import load_plan_cache


def kept_plan_subnets(load=load_plan_cache):
    """Purpose: the subnets of the plan this site last read (its own, by name, and every other site's), as a bundle's
             manifest and a move's check carry them (manual 1.3.7.7, decision 2.1.1.107).
    Inputs:  load — load_plan_cache (tests).
    Returns: [{"name", "cidr"}]: this site's subnets by their names, the other sites' named "another site's subnet";
             [] when no plan was kept (an install without the plan, or one that never read it).
    Fails:   never (a damaged copy is treated as none: the plan's own check still refuses an overlap later).
    Feeds:   backup/make_backup (the manifest's plan_subnets), move/check_new_address."""
    try:
        plan = load() or {}
    except (OSError, ValueError):
        return []
    own = [{"name": s.get("name") or "", "cidr": s["cidr"]} for s in plan.get("subnets") or [] if s.get("cidr")]
    seen = {s["cidr"] for s in own}
    return own + [{"name": "another site's subnet", "cidr": c}
                  for c in dict.fromkeys(plan.get("fabric_networks") or []) if c not in seen]
