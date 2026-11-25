from fabriclib.dns.split.norm_subnet import norm_subnet
from fabriclib.ipam.common.plan_cache import load_plan_cache


def offered_subnets(v, plan=None):
    """Purpose: the networks a zone or a split may name (decision 2.1.4.18, carried from 2.1.4.17 point 2; manual
             1.4.1.13): the host's own LAN first, then every subnet of the site's plan, each once.
    Inputs:  v — settings (lan_cidr); plan — the site's plan (default: the copy this site last read; None or a
             missing copy: the host's LAN alone).
    Returns: [{"cidr" (normalised), "label" ("<cidr> (host's LAN)" or "<cidr> (<name>)")}], the host's LAN first.
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   set_zone_networks, add_split, update_split (what is allowed), split_answers (the networks with a
             view), dns/zone_detail (the Networks row's and a split's choices)."""
    plan = load_plan_cache() if plan is None else plan
    out, seen = [], set()
    host = norm_subnet(v.get("lan_cidr"))
    if host:
        out.append({"cidr": host, "label": f"{host} (host's LAN)"})
        seen.add(host)
    for s in (plan or {}).get("subnets") or []:
        cidr = norm_subnet(s.get("cidr"))
        if cidr and cidr not in seen:
            seen.add(cidr)
            out.append({"cidr": cidr, "label": f"{cidr} ({s.get('name')})" if s.get("name") else cidr})
    return out

