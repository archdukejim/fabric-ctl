import copy

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns.common.fabric_record import fabric_record
from fabriclib.dns.drop_removed_names import drop_removed_names
from fabriclib.dns.split.split_home import split_home


def remove_record(actor, key, rtype, index, expected_name, source="cli", split=None):
    """Purpose: Remove one record from a zone in vars.yaml, only if it is still the one the user saw. Run apply
             afterwards.
    Inputs:  actor — str, who asks (audit).
             key — str zone key; rtype — str record type; index — int position in that type's list.
             expected_name — str, the name the caller showed (so a stale view cannot delete the wrong record).
             source — "cli" (default) or "web". Reads/writes vars.yaml under vars_lock.
             split — the tab (decision 2.1.4.18): a split's index, or None for All networks (the zone's own).
    Returns: the removed record dict. A type list left empty is deleted from the zone. An ACME (DNS-01) TSIG key
             granted the name (or the record with its aliases) loses it, with a note on the key and in the audit,
             unless another record of the zone still has the name (drop_removed_names, decision 2.1.4.12).
    Fails:   ValidationError "record changed since it was shown; reload and try again" (unknown zone or type, index out
             of range, or another name); ValidationError "<name> is provided by fabric (…)" for one of fabric's own
             names (common/fabric_record, 2.1.2.22 item 6): every render adds it back from its setting, so it is
             refused, naming the setting; OSError or yaml.YAMLError from vars_lock / load_vars / save_vars /
             write_audit; split_home's (a stale split).
    Feeds:   agent route POST /v1/zones/<key>/records/delete (fabric-agent, src/agent/);
             menu/edit_dns_zone.
    """
    with vars_lock():
        data = load_vars()
        zone = (data.get("dns") or {}).get(key)
        if zone is None:
            raise ValidationError("record changed since it was shown; reload and try again")
        home = split_home(zone, split)                          # the tab: the zone, or a split (2.1.4.18)
        records = home.get(rtype) or []
        if not 0 <= index < len(records) or (records[index].get("name") or "") != expected_name:
            raise ValidationError("record changed since it was shown; reload and try again")
        own = fabric_record(data, key, rtype, records[index]) if home is zone else None
        if own:
            name = records[index].get("name")
            fqdn = data.get("domain") if name == "@" else f"{name}.{data.get('domain')}"
            raise ValidationError(f"{fqdn} is provided by fabric ({own['service']}, from the setting "
                                  f"{own['setting']}): every apply adds it back, so it cannot be deleted here")
        before = copy.deepcopy(data)
        removed = records.pop(index)
        if not records:
            del home[rtype]
        dropped = drop_removed_names(before, data, key) if home is zone else []   # an ACME key's grant (2.1.4.12)
        save_vars(data)
    write_audit(actor, "DNS_DELETE", f"zone={key}" + (f" split={split}" if home is not zone else "")
                + f" {rtype} {removed}", source)
    for kname, names in dropped:
        write_audit(actor, "TSIG_UPDATE", f"key={kname} dropped {', '.join(names)}: the record was removed", source)
    return removed
