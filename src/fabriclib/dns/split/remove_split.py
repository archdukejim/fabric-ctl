from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns.split.split_home import split_home


def remove_split(actor, key, index, old, source="cli"):
    """Purpose: remove a split with its records (decision 2.1.4.18, manual 1.4.1.13): its networks get the All
             networks tab again. Run apply afterwards. Allowed with the DNS filter off, so a split can be undone.
    Inputs:  actor — who asks (audit); key — the zone's key; index — the split's place; old — its networks as shown
             (comma-joined); source — "cli" or "web".
    Returns: the removed split (dict).
    Fails:   ValidationError: unknown zone; split_home's (stale); OSError or yaml.YAMLError from vars_lock,
             load_vars, save_vars, write_audit.
    Feeds:   agent route POST /v1/zones/<key>/splits/delete (src/agent/post_dns)."""
    with vars_lock():
        data = load_vars()
        zone = (data.get("dns") or {}).get(key)
        if zone is None:
            raise ValidationError("unknown zone")
        split_home(zone, index, old)
        removed = zone["splits"].pop(int(index))
        if not zone["splits"]:
            del zone["splits"]
        save_vars(data)
    write_audit(actor, "DNS_SPLIT_DELETE", f"zone={key} split={index} "
                f"networks={','.join(removed.get('subnets') or [])}", source)
    return removed
