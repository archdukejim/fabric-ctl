import os

from fabriclib.common.paths import FEDERATION_FILE
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.ipam.rules.access_sources import access_sources


def access_web_allow(v, registry_path=FEDERATION_FILE):
    """Purpose: the addresses nginx answers (manual 1.10.4.48.3): the networks the site's access rules allow `web`,
             then what stays outside the rules: this host, fabric's containers, security.firewall_allow and the
             federation's peers (the upstream's and each joined site's address, which reach its API over 443).
    Inputs:  v — fabric vars (host_ip, fabric_subnet, security.firewall_allow, access_sources or the plan last read);
             registry_path — federation.yaml (tests give their own).
    Returns: list of str (networks and addresses), each once, in that order.
    Fails:   OSError or yaml errors reading the registry or a damaged plan copy.
    Feeds:   deploy/check_settings (nginx.conf's geo $fabric_web_denied)."""
    registry = load_registry(registry_path) if os.path.exists(registry_path) else {}
    peers = [p["address"] for p in [registry.get("upstream") or {}, *(registry.get("sites") or {}).values()]
             if p.get("address")]
    own = ["127.0.0.1", v.get("host_ip"), v.get("fabric_subnet") or "10.255.0.0/24"]
    extra = list((v.get("security") or {}).get("firewall_allow") or [])
    return list(dict.fromkeys(a for a in [*access_sources(v)["web"], *own, *extra, *peers] if a))
