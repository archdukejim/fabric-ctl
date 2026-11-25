from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns.split.offered_subnets import offered_subnets
from fabriclib.dns.split.split_checks import forward_only, needs_filter, pick_networks
from fabriclib.dns.split.zone_networks import ALL, zone_networks
from fabriclib.dns.zone_name import zone_name


def _mappable(v, key):
    """Purpose: refuse mapping a zone whose hiding would hide names fabric needs (1.4.1.13): the site's own domain
             (fabric's own names, DHCP's zone) or a zone holding another zone fabric serves.
    Inputs:  v — settings; key — the zone's key.
    Returns: None.
    Fails:   ValidationError saying which, and what to do instead.
    Feeds:   set_zone_networks."""
    if key == "dynamic_zone_var":
        raise ValidationError("the site's own domain is never mapped: it holds fabric's own names and DHCP's zone, "
                              "which every network needs; split it instead")
    fqdn = zone_name(v, key)
    others = [zone_name(v, k) for k in (v.get("dns") or {}) if k != key] + [str(v.get("domain") or "")]
    for other in others:
        if other and other.endswith("." + fqdn):
            raise ValidationError(f"{fqdn} holds the zone {other}, which mapping would hide: map {other} itself, or "
                                  f"split {fqdn}")


def set_zone_networks(actor, key, text, source="cli", plan=None):
    """Purpose: the networks a zone answers (decision 2.1.4.18, manual 1.4.1.13): every network, or some; a client
             elsewhere gets "no such name" for it. Run apply afterwards.
    Inputs:  actor — who asks (audit); key — the zone's key in `dns:`; text — "all", or the networks (CIDRs, commas
             or spaces); source — "cli" or "web"; plan — the site's plan (default: the copy last read).
    Returns: {"old", "new"}: each "all" or the sorted CIDRs.
    Fails:   ValidationError: unknown zone; a reverse zone; pick_networks'; the DNS filter off (some networks); the
             site's own domain or a zone holding another; a network a split holds left out; nothing to change;
             OSError or yaml.YAMLError from vars_lock, load_vars, save_vars, write_audit.
    Feeds:   agent route POST /v1/zones/<key>/networks (src/agent/post_dns)."""
    forward_only(key)
    with vars_lock():
        data = load_vars()
        zone = (data.get("dns") or {}).get(key)
        if zone is None:
            raise ValidationError("unknown zone")
        nets = pick_networks(text, [o["cidr"] for o in offered_subnets(data, plan)])
        if nets != ALL:
            _mappable(data, key)
            needs_filter(data)
            for split in zone.get("splits") or []:
                for cidr in split.get("subnets") or []:
                    if cidr not in nets:
                        raise ValidationError(f"{cidr} is in a split of this zone: remove it from the split first")
        old = zone_networks(zone)
        if old == nets:
            raise ValidationError("nothing to change: the zone already answers those networks")
        if nets == ALL:
            zone.pop("networks", None)
        else:
            zone["networks"] = nets
        save_vars(data)
    shown = nets if nets == ALL else ",".join(nets)
    write_audit(actor, "DNS_NETWORKS", f"zone={key} networks={shown}", source)
    return {"old": old, "new": nets}
