from fabriclib.deploy.check_settings import check_settings
from fabriclib.dns.reverse_zones import reverse_zones
from fabriclib.federation.dns_links import dns_links


def check_rendered(final_vars, secrets, context, federation_file):
    """Purpose: the rendered settings checked, and BIND's zone-list context set from them, the same for an apply and
             for the quick zone path (`dns add-zone` / `remove-zone`, decision 2.1.4.7): the settings check
             (check_settings: DHCP placed and normalized, `dhcp_reverse_zones` where Kea registers PTRs), then the
             reverse zones and the federation links.
    Inputs:  final_vars — render_vars' settings, changed in place (dhcp, dhcp_reverse_zones, ...); secrets — fabric's
             secrets (the federation keys); context — the render context, changed in place (reverse_zone_names,
             federation_links); federation_file — the federation registry's path.
    Returns: {"reverse": reverse_zones()}.
    Fails:   ValidationError from check_settings.
    Feeds:   deploy/apply_deployment, dns/publish_zone_list."""
    check_settings(final_vars)
    reverse = reverse_zones(final_vars)    # reverse zones and their PTRs come from the forward A/AAAA records
    context["reverse_zone_names"] = list(reverse["zones"])
    # federation (manual 1.9 M4): delegations, secondary zones and TSIG keys for the sites next to this one
    context["federation_links"] = dns_links(final_vars, secrets, federation_file)
    return {"reverse": reverse}
