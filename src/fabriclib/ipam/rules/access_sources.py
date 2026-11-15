from fabriclib.ipam.rules.service_sources import service_sources


def access_sources(v):
    """Purpose: the networks each service answers, as the caller's settings hold them (manual 1.10.4.48.3): what an
             apply computed from the plan it just read (`access_sources`, ipam/load_address_plan), else the same
             answer from the plan this site last read, so the firewall at boot and between applies agrees with it.
    Inputs:  v — fabric vars (access_sources when rendered by an apply; host_ip, lan_cidr).
    Returns: service_sources' result.
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   security/firewall_rules, security/apply_docker_firewall, security/apply_ping_rules, ntp/chrony_settings,
             dns/builtin_acls, dns_filter/deploy_resolver, deploy/check_settings."""
    have = v.get("access_sources")
    return have if isinstance(have, dict) and have else service_sources(v)
