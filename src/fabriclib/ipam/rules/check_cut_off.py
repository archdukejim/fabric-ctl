from fabriclib.ipam.rules.constants import GUARDED


def check_cut_off(table, host_vlan):
    """Purpose: whether an access table leaves the host's VLAN without SSH or the console (manual 1.10.4.48.6,
             decision 2.1.10.57).
    Inputs:  table — access_table's shape, as it would be; host_vlan — the host's VLAN's reference, or None (another
             site's plan, or no VLAN holding the host: lan_cidr, which is always allowed, is then the host's).
    Returns: the refusal's text, or None when the host's VLAN keeps both.
    Fails:   never.
    Feeds:   set_access, the dev preview (webui/devpreview/fake_ipam)."""
    if not host_vlan or host_vlan not in table:
        return None
    for service in GUARDED:
        if table[host_vlan].get(service) != "allow":
            return (f"this leaves the host's VLAN ({host_vlan}) without {service}: the host would be reached only at "
                    "its console; add --force on the command line, as root on the host, to mean it")
    return None
