from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.rules.constants import SERVICES
from fabriclib.ipam.rules.decide_rule import decide_rule
from fabriclib.ipam.rules.effective_rules import effective_rules
from fabriclib.ipam.rules.network_names import network_names
from fabriclib.ipam.rules.rule_networks import rule_networks

NO_PLAN = object()


def service_sources(v, plan=NO_PLAN, rules=None):
    """Purpose: the networks each of fabric's services answers (manual 1.10.4.48.1, 1.10.4.48.3): every network the
             site knows, decided by its rules in order, the implied deny last. Every layer of enforcement (the
             firewall, Kea, BIND, the resolver, chrony, nginx, FreeRADIUS) is built from this one answer.
    Inputs:  v — fabric vars (host_ip, lan_cidr); plan — the site's plan (default: the copy this site last read,
             plan_cache; None for no plan); rules — the rules to decide by (default effective_rules(plan)).
    Returns: {service: [CIDR, ...]} for every service of constants.SERVICES, each list in rule_networks' order
             (the host's networks first).
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   security/firewall_rules, security/apply_docker_firewall, security/apply_ping_rules, dns/builtin_acls,
             dns_filter/deploy_resolver, ntp/chrony_settings, deploy/check_settings (nginx, FreeRADIUS),
             ipam/plan_to_dhcp's callers (Kea), check_cut_off, rule_warnings."""
    plan = load_plan_cache() if plan is NO_PLAN else plan
    rules = effective_rules(plan) if rules is None else rules
    nets = rule_networks(v, plan)
    return {service: [c for c in nets["any"] if decide_rule(rules, network_names(c, nets), service)[0] == "allow"]
            for service in SERVICES}
