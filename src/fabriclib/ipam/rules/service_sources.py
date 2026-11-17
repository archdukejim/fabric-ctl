import ipaddress

from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.rules.access_table import access_table
from fabriclib.ipam.rules.constants import ANY, EXTERNAL, FABRIC, SERVICES
from fabriclib.ipam.rules.network_in import network_in
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


def service_sources(v, plan=NO_PLAN, table=None):
    """Purpose: the networks each of fabric's services answers (manual 1.10.4.48.10, 1.10.4.48.3): from the site's
             access table, the subnets of each VLAN allowed it (the host's first; lan_cidr always, when no VLAN holds
             the host), the other sites' networks when `fabric` is, and, when `any` is, 0.0.0.0/0 less every known
             network denied it, as the fewest CIDRs, so each layer keeps an allow list (2.1.10.62). Every layer of
             enforcement (the firewall, Kea, BIND, the resolver, chrony, nginx, FreeRADIUS) is built from this.
    Inputs:  v — fabric vars (host_ip, lan_cidr); plan — the site's plan (default: the copy this site last read,
             plan_cache; None for no plan); table — the table to decide by (default access_table(plan, ...)).
    Returns: {service: [CIDR, ...]} for every service of constants.SERVICES.
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   security/firewall_rules, security/apply_docker_firewall, security/apply_ping_rules, dns/builtin_acls,
             dns_filter/deploy_resolver, ntp/chrony_settings, deploy/check_settings (nginx, FreeRADIUS),
             ipam/plan_to_dhcp's callers (Kea)."""
    plan = load_plan_cache() if plan is NO_PLAN else plan
    nets = rule_networks(v, plan)
    table = access_table(plan, nets["host_vlan"]) if table is None else table
    order = ([nets["host_vlan"]] if nets["host_vlan"] else []) + [r for r in nets["vlans"] if r != nets["host_vlan"]]
    others = [c for c in nets["fabric"] if c not in nets["site"]]
    out = {}
    for service in SERVICES:
        allowed = [] if nets["host_vlan"] else list(nets["host"])
        for ref in order:
            if table.get(ref, {}).get(service) == "allow":
                allowed += [c for c in nets["vlans"][ref] if c not in allowed]
        if table[FABRIC][service] == "allow":
            allowed += [c for c in others if c not in allowed]
        if table[ANY][service] == "allow":
            rest = _rest([c for c in nets["fabric"] if c not in allowed])
            allowed = [c for c in allowed if not network_in(c, rest)] + rest
        out[service] = allowed
    return out
