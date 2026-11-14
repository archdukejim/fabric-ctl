import ipaddress

from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.rules.constants import EXTERNAL, SERVICES
from fabriclib.ipam.rules.decide_rule import decide_rule
from fabriclib.ipam.rules.effective_rules import effective_rules
from fabriclib.ipam.rules.network_in import network_in
from fabriclib.ipam.rules.network_names import network_names
from fabriclib.ipam.rules.rule_networks import rule_networks

NO_PLAN = object()


def _rest(denied):
    """Purpose: the IPv4 space less the networks denied, as the fewest CIDRs that cover it.
    Inputs:  denied — list of CIDR str (any that does not parse, or is not IPv4, is left out).
    Returns: list of CIDR str, ascending.
    Fails:   never.
    Feeds:   service_sources."""
    out = [ipaddress.ip_network(EXTERNAL)]
    for text in denied:
        try:
            cut = ipaddress.ip_network(text, strict=False)
        except ValueError:
            continue
        if cut.version != 4:
            continue
        kept = []
        for net in out:
            if cut.subnet_of(net):
                kept += list(net.address_exclude(cut))
            elif not net.subnet_of(cut):
                kept.append(net)
        out = kept
    return [str(n) for n in ipaddress.collapse_addresses(out)]


def service_sources(v, plan=NO_PLAN, rules=None):
    """Purpose: the networks each of fabric's services answers (manual 1.10.4.48.1, 1.10.4.48.3): every network the
             domain knows, then the rest of the IPv4 space, decided by the site's rules in order, the implied deny
             last. When the rest is allowed (a rule from `any`, 2.1.10.62), the list is 0.0.0.0/0 less every known
             network denied, so each layer keeps an allow list. Every layer of enforcement (the firewall, Kea, BIND,
             the resolver, chrony, nginx, FreeRADIUS) is built from this one answer.
    Inputs:  v — fabric vars (host_ip, lan_cidr); plan — the site's plan (default: the copy this site last read,
             plan_cache; None for no plan); rules — the rules to decide by (default effective_rules(plan)).
    Returns: {service: [CIDR, ...]} for every service of constants.SERVICES: the known networks allowed, in
             rule_networks' order (the host's first), then, when the rest is allowed, the CIDRs that cover it (a
             known network those already cover is not listed again).
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   security/firewall_rules, security/apply_docker_firewall, security/apply_ping_rules, dns/builtin_acls,
             dns_filter/deploy_resolver, ntp/chrony_settings, deploy/check_settings (nginx, FreeRADIUS),
             ipam/plan_to_dhcp's callers (Kea), check_cut_off, rule_warnings."""
    plan = load_plan_cache() if plan is NO_PLAN else plan
    rules = effective_rules(plan) if rules is None else rules
    nets = rule_networks(v, plan)
    out = {}
    for service in SERVICES:
        allowed = [c for c in nets["all"] if decide_rule(rules, network_names(c, nets), service)[0] == "allow"]
        if EXTERNAL in allowed:
            rest = _rest([c for c in nets["fabric"] if c not in allowed])
            allowed = [c for c in allowed if c != EXTERNAL and not network_in(c, rest)] + rest
        out[service] = allowed
    return out
