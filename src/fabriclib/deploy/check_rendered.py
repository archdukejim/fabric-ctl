from fabriclib.deploy.check_settings import check_settings
from fabriclib.dns.reverse_by_hand import reverse_by_hand
from fabriclib.dns.reverse_zones import reverse_zones
from fabriclib.federation.dns_links import dns_links
from fabriclib.ipam.load_address_plan import load_address_plan


def check_rendered(final_vars, secrets, context, federation_file):
    """Purpose: the rendered settings made whole and checked, and BIND's zone-list context set from them, the same
             for an apply and for the quick zone path (`dns add-zone` / `remove-zone`, decision 2.1.4.7, extended by
             2.1.10.21): the site's address plan (load_address_plan: the DHCP subnets and static names, manual
             1.10.4.14), the settings check (check_settings: DHCP placed and normalized, `dhcp_reverse_zones` where
             Kea registers PTRs), then the reverse zones, the PTRs set by hand that Kea's key may never replace
             (2.1.10.20) and the federation links.
    Inputs:  final_vars — render_vars' settings, changed in place (dhcp, dns, dhcp_served, dhcp_reverse_zones, ...);
             secrets — fabric's secrets (the agent's password for the plan, the federation keys); context — the
             render context, changed in place (reverse_zone_names, reverse_by_hand, federation_links);
             federation_file — the federation registry's path.
    Returns: {"lines": list of str to show (where the plan came from, names left out), "reverse": reverse_zones()}.
    Fails:   ValidationError from load_address_plan (DHCP on and no plan to be had) or check_settings; OSError keeping
             the plan read.
    Feeds:   deploy/apply_deployment, dns/publish_zone_list."""
    lines = load_address_plan(final_vars, secrets)
    check_settings(final_vars)
    reverse = reverse_zones(final_vars)    # reverse zones and their PTRs come from the forward A/AAAA records
    context["reverse_zone_names"] = list(reverse["zones"])
    context["reverse_by_hand"] = reverse_by_hand(reverse)      # PTRs DHCP's key may never replace (2.1.10.20)
    # federation (manual 1.9 M4): delegations, secondary zones and TSIG keys for the sites next to this one
    context["federation_links"] = dns_links(final_vars, secrets, federation_file)
    return {"lines": lines, "reverse": reverse}
