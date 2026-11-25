import copy

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns.common.fabric_record import fabric_record
from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.dns.split.offered_subnets import offered_subnets
from fabriclib.dns.split.split_checks import forward_only, free_networks, needs_filter, pick_networks


def add_split(actor, key, text, source="cli", plan=None):
    """Purpose: a new split of a zone (decision 2.1.4.18, manual 1.4.1.13): some of its networks get a tab of their
             own, starting as a copy of the All networks tab's records less fabric's own names (which answer in
             every tab). Run apply afterwards.
    Inputs:  actor — who asks (audit); key — the zone's key; text — the split's networks (CIDRs); source — "cli" or
             "web"; plan — the site's plan (default: the copy last read).
    Returns: {"index" (the new split's place), "subnets"}.
    Fails:   ValidationError: unknown zone; a reverse zone; the DNS filter off; pick_networks' (every network is not
             a split's); free_networks'; OSError or yaml.YAMLError from vars_lock, load_vars, save_vars,
             write_audit.
    Feeds:   agent route POST /v1/zones/<key>/splits (src/agent/post_dns)."""
    forward_only(key)
    with vars_lock():
        data = load_vars()
        zone = (data.get("dns") or {}).get(key)
        if zone is None:
            raise ValidationError("unknown zone")
        needs_filter(data)
        nets = pick_networks(text, [o["cidr"] for o in offered_subnets(data, plan)], allow_all=False)
        free_networks(zone, nets)
        split = {"subnets": nets}
        for rtype in RECORD_TYPES:
            recs = [copy.deepcopy(r) for r in zone.get(rtype) or []
                    if isinstance(r, dict) and not fabric_record(data, key, rtype, r)]
            if recs:
                split[rtype] = recs
        zone.setdefault("splits", []).append(split)
        index = len(zone["splits"]) - 1
        save_vars(data)
    write_audit(actor, "DNS_SPLIT_ADD", f"zone={key} split={index} networks={','.join(nets)}", source)
    return {"index": index, "subnets": nets}
