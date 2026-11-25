from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns.split.offered_subnets import offered_subnets
from fabriclib.dns.split.split_checks import free_networks, needs_filter, pick_networks
from fabriclib.dns.split.split_home import split_home


def update_split(actor, key, index, old, text, source="cli", plan=None):
    """Purpose: change which networks a split holds (decision 2.1.4.18, manual 1.4.1.13); its records stay. Run
             apply afterwards.
    Inputs:  actor — who asks (audit); key — the zone's key; index — the split's place; old — its networks as shown
             (comma-joined); text — the new networks; source — "cli" or "web"; plan — the site's plan.
    Returns: {"old": [CIDR], "new": [CIDR]}.
    Fails:   ValidationError: unknown zone; split_home's (stale); the DNS filter off; pick_networks'; free_networks';
             nothing to change; OSError or yaml.YAMLError from vars_lock, load_vars, save_vars, write_audit.
    Feeds:   agent route POST /v1/zones/<key>/splits/update (src/agent/post_dns)."""
    with vars_lock():
        data = load_vars()
        zone = (data.get("dns") or {}).get(key)
        if zone is None:
            raise ValidationError("unknown zone")
        split = split_home(zone, index, old)
        needs_filter(data)
        nets = pick_networks(text, [o["cidr"] for o in offered_subnets(data, plan)], allow_all=False)
        free_networks(zone, nets, skip=int(index))
        before = list(split.get("subnets") or [])
        if before == nets:
            raise ValidationError("nothing to change: the split already holds those networks")
        split["subnets"] = nets
        save_vars(data)
    write_audit(actor, "DNS_SPLIT_UPDATE", f"zone={key} split={index} networks={','.join(before)} -> "
                f"{','.join(nets)}", source)
    return {"old": before, "new": nets}
