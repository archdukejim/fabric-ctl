import copy

# what load_address_plan lays over the settings from the site's address plan at every apply (manual 1.10.4.14)
PLAN_DHCP_KEYS = ("subnets", "options", "option_defs", "client_classes")


def vars_to_save(final_vars, settings):
    """Purpose: the vars.yaml an apply installs: the checked settings, without what was read from the site's address
             plan for this render only (manual 1.10.4.14, 2.3.10.10.4). The plan's subnets, the option sets laid over
             the settings' and its published names stay in the domain; written into vars.yaml they would read as the
             settings' own next time: the 0.7 commands would edit them there (plan_holds_subnets false) and the
             upgrade would drop those edits, and a plan name would become a settings record that outlives its
             address.
    Inputs:  final_vars — the settings as rendered and checked (check_rendered, the plan laid over them); settings —
             a copy of the same settings taken before the plan was laid over them (render_vars' result).
    Returns: a new dict: final_vars without `dhcp.subnets` when `settings` has none (settings that still carry
             them, before the upgrade, keep them as checked and placed), with `dhcp.options`, `dhcp.option_defs`,
             `dhcp.client_classes` and `dns.dynamic_zone_var.A` as `settings` holds them (absent where it has none).
             What check_settings derives (dhcp_served, dhcp_reverse_zones) is kept: it is recomputed at every apply.
    Fails:   never.
    Feeds:   deploy/apply_deployment (the rendered vars.yaml, installed by install_fabric_tree)."""
    out = copy.deepcopy(final_vars)
    if isinstance(out.get("dhcp"), dict):
        before = settings.get("dhcp") if isinstance(settings.get("dhcp"), dict) else {}
        if "subnets" not in before:                   # the plan's; settings still carrying them keep them placed
            out["dhcp"].pop("subnets", None)
        for key in PLAN_DHCP_KEYS[1:]:
            if key in before:
                out["dhcp"][key] = copy.deepcopy(before[key])
            else:
                out["dhcp"].pop(key, None)
    zone = ((out.get("dns") or {}).get("dynamic_zone_var")) if isinstance(out.get("dns"), dict) else None
    if isinstance(zone, dict):
        dns_before = settings.get("dns") if isinstance(settings.get("dns"), dict) else {}
        had = dns_before.get("dynamic_zone_var") if isinstance(dns_before.get("dynamic_zone_var"), dict) else None
        if had is None and set(zone) <= {"A"}:            # the plan's names made the zone's entry: none before
            out["dns"].pop("dynamic_zone_var")
            if not out["dns"] and "dns" not in settings:
                out.pop("dns")
        elif had is not None and "A" in had:
            zone["A"] = copy.deepcopy(had["A"])
        else:
            zone.pop("A", None)
    return out
