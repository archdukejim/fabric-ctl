from fabriclib.common.errors import ValidationError
from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.dns.split.norm_subnet import norm_subnet
from fabriclib.dns.split.offered_subnets import offered_subnets
from fabriclib.dns.split.reach import ALL, reach
from fabriclib.dns.split.split_needs_filter import WHY

def default_reach(v, offered):
    """Purpose: the subnets a new record starts with (decision 2.1.4.17): the host's LAN alone; every subnet when the
             DNS filter is off, since split answers need it (2.1.4.16, open point 2.1.4.17.3).
    Inputs:  v — settings (dns_filter); offered — offered_subnets().
    Returns: "all" or [the host's LAN].
    Fails:   never.
    Feeds:   record_subnets (a form that names none), dns/zone_detail (the add row), menu/edit_dns_zone."""
    if str(v.get("dns_filter") or "bind").strip().lower() != "bind" or not offered:
        return ALL
    return [offered[0]["cidr"]]


def record_subnets(key, rtype, record, form, zone, v, index=None, plan=None, old=None):
    """Purpose: the subnets a record answers, as typed, checked (decision 2.1.4.17, manual 1.4.1.12): each the host's
             LAN or a subnet of the site's plan, or every subnet; in one of the site's own forward zones; only with
             the DNS filter on (2.1.4.16); never a CNAME beside another record of the same name reaching a subnet in
             common.
    Inputs:  key — the zone's key in `dns:`; rtype — the record's type; record — validate_record's fields; form —
             the typed fields: subnets ("all", or CIDRs joined by commas or spaces; left out: a new record's
             default, default_reach, or an edited record's own, `old`); zone — the zone's records ({type: [record]});
             v — settings (lan_cidr, dns_filter); index — the record's place in its type's list when it is being
             replaced (left out of the checks), else None; plan — the site's plan (default: the copy last read);
             old — the record being replaced, or None.
    Returns: record with "subnets" (a sorted list of CIDRs), or without it for every subnet.
    Fails:   ValidationError: no subnet picked; "all" beside a subnet; a subnet that is not one, or neither the host's
             LAN nor in the plan; subnets in a reverse zone; the DNS filter off; a CNAME clash.
    Feeds:   add_record, update_record."""
    record = {k: val for k, val in record.items() if k not in ("subnets", "vlan")}
    offered = offered_subnets(v, plan)
    text = form.get("subnets")
    if text is None:
        picked = reach(old) if old is not None else default_reach(v, offered)
    else:
        words = [w for w in str(text).replace(",", " ").split() if w]
        if not words:
            raise ValidationError("pick at least one subnet for the record, or every subnet")
        if ALL in [w.lower() for w in words]:
            if len(words) > 1:
                raise ValidationError("every subnet already holds the others: pick it alone, or only subnets")
            picked = ALL
        else:
            known = {o["cidr"] for o in offered}
            picked = []
            for w in words:
                cidr = norm_subnet(w)
                if not cidr:
                    raise ValidationError(f"{w} is not a subnet (write it as 10.77.0.0/24)")
                if cidr not in known:
                    raise ValidationError(f"{cidr} is neither the host's LAN nor a subnet of the site's plan (it has "
                                          f"{', '.join(sorted(known)) or 'none'})")
                picked.append(cidr)
            picked = sorted(set(picked))
    if picked == ALL:
        return record
    if str(key).endswith(".arpa"):
        raise ValidationError("a reverse zone answers every subnet: a record for some subnets goes in a forward zone")
    if str(v.get("dns_filter") or "bind").strip().lower() != "bind":
        raise ValidationError(WHY)
    for t in RECORD_TYPES:
        for i, r in enumerate(zone.get(t) or []):
            if r.get("name") != record["name"] or (t == rtype and i == index):
                continue
            theirs = reach(r)            # every-subnet records are overridden in a subnet's view: no clash
            if theirs != ALL and set(theirs) & set(picked) and "CNAME" in (rtype, t):
                raise ValidationError(f"{record['name']}: a CNAME cannot sit beside another record of the same name "
                                      "for the same subnet")
    return {**record, "subnets": picked}
