from fabriclib.dns.split.norm_subnet import norm_subnet
from fabriclib.ipam.common.plan_cache import load_plan_cache


def offered_subnets(v, plan=None):
    """Purpose: the subnets a record may name (decision 2.1.4.17, point 2; manual 1.4.1.12): the host's own LAN first,
             then every subnet of the site's plan, each once.
    Inputs:  v — settings (lan_cidr); plan — the site's plan (default: the copy this site last read; None or a
             missing copy: the host's LAN alone).
    Returns: [{"cidr" (normalised), "label" ("<cidr> (host's LAN)" or "<cidr> (<name>)")}], the host's LAN first.
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   record_subnets (what is allowed), dns/zone_detail (the column's choices), menu/edit_dns_zone."""
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

