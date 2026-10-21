from fabriclib.common.errors import ValidationError
from fabriclib.deploy.check_samba_settings import check_samba_settings
from fabriclib.deploy.check_service_settings import check_service_settings
from fabriclib.dhcp.client_networks import client_networks
from fabriclib.dhcp.dhcp_reverse_zones import dhcp_reverse_zones
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp
from fabriclib.dhcp.place_subnets import place_subnets
from fabriclib.dns_filter.check_filter_settings import check_filter_settings
from fabriclib.keycloak.signin_levels import signin_level
from fabriclib.ntp.normalize_ntp import normalize_ntp
from fabriclib.system.host_networks import host_networks


def check_settings(final_vars):
    """Purpose: the rendered settings that are checked before anything is rendered or installed.
    Inputs:  final_vars — rendered settings; its `dhcp` is replaced by the normalized one, each subnet placed on
             this host's interfaces (place_subnets: fabric's address for it), and `dhcp_served` set (client_networks:
             the subnets and addresses the templates open and listen on, manual 1.10.3.3) and `dhcp_reverse_zones`
             (where Kea registers PTRs: dns/reverse_zones, BIND's grants, Kea's reverse DDNS; 2.1.10.7).
    Returns: None.
    Fails:   ValidationError from normalize_dhcp (DHCP subnets, pools, reservations, dhcp.ntp), place_subnets (an
             interface this host lacks, a subnet on no served interface and not relayed) or normalize_ntp
             (ntp_servers, ntp_serve, ntp_set_clock), from check_samba_settings (the Windows domain), for a
             dns_filter other than bind or none, from
             check_filter_settings (the BIND resolver's lists, rules and upstreams), from signin_level (a second
             factor that is not a level), or for a pki_manual_max_days that is not a whole number of days, or from
             check_service_settings (images, fabric's container addresses).
    Feeds:   apply_deployment."""
    check_service_settings(final_vars)
    final_vars["dhcp"] = normalize_dhcp(final_vars)
    if final_vars.get("install_kea"):                 # on the host: its interfaces; elsewhere ({}) served from host_ip
        final_vars["dhcp"] = place_subnets(final_vars["dhcp"], final_vars.get("host_ip"), host_networks() or None)
    final_vars["dhcp_served"] = client_networks(final_vars)
    final_vars["dhcp_reverse_zones"] = dhcp_reverse_zones(final_vars)
    normalize_ntp(final_vars)
    if final_vars.get("dns_filter") not in ("none", "bind"):
        raise ValidationError(f"dns_filter must be bind or none (got {final_vars.get('dns_filter')!r})")
    if final_vars.get("dns_filter") == "bind":
        check_filter_settings(final_vars)
    for key in ("signin_admin_second_factor", "signin_everyone_second_factor"):
        final_vars[key] = signin_level(final_vars.get(key))
    check_samba_settings(final_vars)
    days = str(final_vars.get("pki_manual_max_days", 1825)).strip()
    if not days.isdigit() or int(days) < 1:          # the cap on certificates issued by hand (pki/common/valid_days)
        raise ValidationError(f"pki_manual_max_days must be a whole number of days, at least 1 (got {days!r})")
    final_vars["pki_manual_max_days"] = int(days)
