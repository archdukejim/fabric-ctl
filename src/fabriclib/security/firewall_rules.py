import os

from fabriclib.federation.common.load_registry import load_registry
from fabriclib.ipam.rules.access_sources import access_sources
from fabriclib.ntp.chrony_settings import chrony_settings

# the domain controller's ports (manual 1.6.5.4), besides 53 (BIND, published by Docker): Kerberos, the RPC endpoint
# mapper, LDAP (CLDAP on UDP), SMB, kpasswd, LDAPS, the global catalog, then its RPC range
AD_TCP = "88,135,389,445,464,636,3268,3269"
AD_UDP = "88,389,464"


def firewall_rules(v, config_dir):
    """Purpose: the networks and interfaces fabric's host firewall opens, computed once for the setup step and for
             the consent question that asks before it (manual 1.2.9).
    Inputs:  v — vars: lan_cidr, security.firewall_allow (extra CIDRs), ntp_serve (default True; chrony_settings
             decides its networks), install_kea + dhcp.interfaces; config_dir — the install's config folder
             (federation.yaml, for chrony's networks and the federation's peers); ad_rpc_ports + fabric_subnet
             (the DC).
    Returns: {"ssh": [CIDR, ...] (SSH, on the ports sshd listens on: the networks the site's access rules allow
             `ssh`, then security.firewall_allow), "ntp": [CIDR, ...] (123/udp: chrony's, the rules' `ntp`),
             "dhcp": [interface, ...] (67/udp; Kea's own configuration decides which VLANs it answers),
             "ad": ["<proto>@<CIDR>@<ports>", ...] (the domain controller's ports: the networks the rules allow
             `ad`, security.firewall_allow, fabric's container subnet and the federation's peers: the upstream's
             and every joined site's address)} (manual 1.10.4.48.3).
    Fails:   KeyError without fabric_subnet; ValidationError from chrony_settings for invalid NTP settings.
    Feeds:   setup/configure_firewall, consent/plan_firewall."""
    security = v.get("security") or {}
    ntp = chrony_settings(v, os.path.join(config_dir, "federation.yaml"))["allow"] if v.get("ntp_serve", True) else []
    dhcp = list((v.get("dhcp") or {}).get("interfaces") or []) if v.get("install_kea") else []
    sources = access_sources(v)                 # the site's access rules (1.10.4.48.3)
    extra = list(security.get("firewall_allow") or [])
    ssh = list(dict.fromkeys([*sources["ssh"], *extra]))
    ad = []
    rpc = str(v.get("ad_rpc_ports") or "49152-49251").replace("-", ":")
    # Keycloak and FreeRADIUS reach the DC at fabric_net's gateway (2.1.2.15); the DCs of the sites next to this
    # one replicate with it (manual 1.9.8.5): its upstream's and each joined site's address
    registry = load_registry(os.path.join(config_dir, "federation.yaml"))
    peers = [p["address"] for p in [registry.get("upstream") or {}, *registry.get("sites", {}).values()]
             if p.get("address")]
    peers = [f"{a}/{128 if ':' in a else 32}" for a in peers]
    ad_from = list(dict.fromkeys([*sources["ad"], *extra, v["fabric_subnet"], *peers]))
    for cidr in ad_from:
        ad += [f"tcp@{cidr}@{AD_TCP},{rpc}", f"udp@{cidr}@{AD_UDP}"]
    return {"ssh": ssh, "ntp": list(ntp), "dhcp": dhcp, "ad": ad}
