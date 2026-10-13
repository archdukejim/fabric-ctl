from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns.common.fabric_record import fabric_record


def remove_record(actor, key, rtype, index, expected_name, source="cli"):
    """Purpose: Remove one record from a zone in vars.yaml, only if it is still the one the user saw. Run apply
             afterwards.
    Inputs:  actor — str, who asks (audit).
             key — str zone key; rtype — str record type; index — int position in that type's list.
             expected_name — str, the name the caller showed (so a stale view cannot delete the wrong record).
             source — "cli" (default) or "web". Reads/writes vars.yaml under vars_lock.
    Returns: the removed record dict. A type list left empty is deleted from the zone.
    Fails:   ValidationError "record changed since it was shown; reload and try again" (unknown zone or type, index out
             of range, or another name); ValidationError "<name> is provided by fabric (…)" for one of fabric's own
             names (common/fabric_record, 2.1.2.22 item 6): every render adds it back from its setting, so it is
             refused, naming the setting; OSError or yaml.YAMLError from vars_lock / load_vars / save_vars /
             write_audit.
    Feeds:   agent route POST /v1/zones/<key>/records/delete (fabric-agent, src/agent/);
             menu/edit_dns_zone.
    """
    with vars_lock():
        data = load_vars()
        records = ((data.get("dns") or {}).get(key) or {}).get(rtype) or []
        if not 0 <= index < len(records) or (records[index].get("name") or "") != expected_name:
            raise ValidationError("record changed since it was shown; reload and try again")
        own = fabric_record(data, key, rtype, records[index])
        if own:
            name = records[index].get("name")
            fqdn = data.get("domain") if name == "@" else f"{name}.{data.get('domain')}"
            raise ValidationError(f"{fqdn} is provided by fabric ({own['service']}, from the setting "
                                  f"{own['setting']}): every apply adds it back, so it cannot be deleted here")
        removed = records.pop(index)
        if not records:
            del data["dns"][key][rtype]
        save_vars(data)
    write_audit(actor, "DNS_DELETE", f"zone={key} {rtype} {removed}", source)
    return removed
