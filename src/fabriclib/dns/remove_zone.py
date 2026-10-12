import copy
import json

from fabriclib.common.errors import NotPublished, ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns.publish_zone_list import publish_zone_list


def _named_by(data, name):
    """Purpose: the TSIG keys and ACL policies that name a zone (they must go first, on the Keys page).
    Inputs:  data — the vars (tsig_keys, bind_acl_policies; a key or policy without a domain is the site's own zone);
             name — the zone's name.
    Returns: list of str such as "TSIG key npm-certbot", "ACL policy certbots".
    Fails:   never.
    Feeds:   remove_zone."""
    domain = str(data.get("domain") or "")

    def zone_of(item):
        return str((item or {}).get("domain") or domain).replace("{{ domain }}", domain).rstrip(".").lower()

    named = [f"TSIG key {k.get('name')}" for k in data.get("tsig_keys") or [] if zone_of(k) == name]
    named += [f"ACL policy {acl}" for acl, pol in (data.get("bind_acl_policies") or {}).items()
              if zone_of(pol) == name]
    return named


def remove_zone(actor, key, confirm, source="cli"):
    """Purpose: remove a forward zone with its records, its zone file and journal (manual 1.4.1.3, decision 2.1.4.5):
             BIND and the DNS filter's resolver stop answering for it within seconds (publish_zone_list), no apply
             needed. The records removed are kept in the audit entry.
    Inputs:  actor — who asks (audit); key — the zone's key in `dns:`; confirm — the zone's name typed again; source —
             "cli" or "web". Reads and writes vars.yaml under vars_lock.
    Returns: {"key", "name", "records" (how many went)}.
    Fails:   ValidationError with the reason, and nothing changed: an unknown zone; the site's own zone; confirm not the
             zone's name; a TSIG key or ACL policy naming it; or the publish failing (BIND or the resolver refusing):
             then the vars are put back, both configurations rendered again, and the message says why. OSError or
             yaml.YAMLError from the vars file or the audit log.
    Feeds:   agent route POST /v1/zones/<key>/delete (fabric-agent, src/agent/post_dns.py); menu/edit_dns ("r")."""
    with vars_lock():
        data = load_vars()
        zones = data.get("dns") or {}
        if key == "dynamic_zone_var":
            raise ValidationError("the site's own zone cannot be removed")
        if key not in zones:
            raise ValidationError("unknown zone")
        name = key
        if str(confirm or "").strip().rstrip(".").lower() != name:
            raise ValidationError(f"type the zone's name, {name}, to remove it")
        named = _named_by(data, name)
        if named:
            raise ValidationError(f"{name} is still named by {', '.join(named)}: remove them first (Keys page)")
        before = copy.deepcopy(data)
        records = zones.pop(key) or {}
        count = sum(len(v) for v in records.values() if isinstance(v, list))
        save_vars(data)
        try:
            publish_zone_list(removed=(name,))
        except NotPublished as e:           # refused before BIND's files were touched: only the vars to put back
            save_vars(before)
            raise ValidationError(f"zone {name} not removed: {e}")
        except Exception as e:
            save_vars(before)
            try:
                publish_zone_list(added=(name,))
            except Exception as again:          # the vars are back; say both
                raise ValidationError(f"zone {name} not removed: {e}. Putting the old zone list back failed too: "
                                      f"{again}; run an apply")
            raise ValidationError(f"zone {name} not removed: {e}")
    write_audit(actor, "DNS_ZONE_DELETE", f"zone={name} records={count} {json.dumps(records, sort_keys=True)}",
                source)
    return {"key": key, "name": name, "records": count}
