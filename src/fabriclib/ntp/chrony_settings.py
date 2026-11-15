import ipaddress

from fabriclib.federation.common.load_registry import load_registry
from fabriclib.ipam.rules.access_sources import access_sources
from fabriclib.ntp.normalize_ntp import normalize_ntp


def _allowed(v):
    """Purpose: the networks chrony answers (ntp_serve): those the site's access rules allow `ntp` (manual
             1.10.4.48.3), then security.firewall_allow, an explicit relaxation outside the rules.
    Inputs:  v — vars: access_sources (or host_ip, lan_cidr and the plan last read), security.firewall_allow.
    Returns: list of network strings, deduplicated, in that order; entries that are not networks are left out.
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   chrony_settings."""
    nets = [*access_sources(v)["ntp"], *((v.get("security") or {}).get("firewall_allow") or [])]
    out = []
    for n in nets:
        try:
            net = str(ipaddress.ip_network(str(n), strict=False))
        except ValueError:
            continue
        if net not in out:
            out.append(net)
    return out


def chrony_settings(v, registry_path):
    """Purpose: what chrony.conf.j2 needs: the sources (the upstream site first) and the networks served.
    Inputs:  v — vars (see normalize_ntp, _allowed); registry_path — config/federation.yaml.
    Returns: {"sources": [{"host", "nts", "pool", "prefer"}], "allow": [network], "serve": bool, "ad_ntp_signd_dir":
             the DC's time-signing socket folder (2.1.13.1)}.
    Fails:   ValidationError from normalize_ntp; yaml/OSError from load_registry.
    Feeds:   deploy_chrony; tests/ntp/run.py, tests/render.py."""
    sources = normalize_ntp(v)
    up = (load_registry(registry_path).get("upstream") or {}).get("address")
    try:
        ipaddress.ip_address(str(up))
    except ValueError:
        up = None
    if up and up not in [s["host"] for s in sources]:
        sources = [{"host": up, "nts": False, "pool": False, "prefer": True}] + sources
    return {"sources": sources, "allow": _allowed(v), "serve": bool(v.get("ntp_serve", True)),
            "ad_ntp_signd_dir": v.get("ad_ntp_signd_dir") or "/var/lib/samba/ntp_signd"}
