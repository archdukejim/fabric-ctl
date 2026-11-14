from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.rules.access_sources import access_sources
from fabriclib.ipam.rules.rule_networks import rule_networks


def access_denied(v):
    """Purpose: for each service, the networks the site knows that its access rules do not allow (manual
             1.10.4.48.3): what a service with a silent list of its own (BIND's and the resolver's `blackhole`) is
             told to ignore, so even with the firewall off they get no answer, not a refusal.
    Inputs:  v — fabric vars (access_networks and access_sources when an apply set them; else host_ip, lan_cidr and
             the plan last read).
    Returns: {service: [CIDR, ...]}, in rule_networks' order.
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   deploy/check_settings (the templates' access_denied), dns_filter/deploy_resolver."""
    known = v.get("access_networks")
    if not isinstance(known, list):
        known = rule_networks(v, load_plan_cache())["any"]
    sources = access_sources(v)
    return {service: [n for n in known if n not in allowed] for service, allowed in sources.items()}
