from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.dns.split.record_vlan import record_vlan
from fabriclib.dns.tsig_record_notice import tsig_record_notice
from fabriclib.dns.validate_record import validate_record


def add_record(actor, key, rtype, form, source="cli"):
    """Purpose: Validate a DNS record and append it to one zone in vars.yaml (`dns:`). Run apply afterwards to publish
             it.
    Inputs:  actor — str, who asks (audit).
             key — str, the zone key in `dns:` (dynamic_zone_var is the main domain).
             rtype — one of RECORD_TYPES (A, AAAA, CNAME, MX, TXT, SRV).
             form — dict of user fields as validate_record expects (name, ip, target, text, priority, weight, port),
             and vlan (a VLAN of the site's plan: the record answers that VLAN alone, split/record_vlan, 2.1.4.16).
             source — "cli" (default) or "web". Reads and writes vars.yaml under vars_lock.
    Returns: the stored record dict, shaped per validate_record (e.g. {"name", "ip"} for A), with "vlan" when given.
    Fails:   ValidationError "unsupported record type", "unknown zone", "a CNAME with that name already exists" (for
             the same VLAN, or everyone), or one from validate_record or record_vlan; OSError or yaml.YAMLError
             from vars_lock / load_vars / save_vars / write_audit.
    Feeds:   agent route POST /v1/zones/<key>/records (fabric-agent, src/agent/, called by the web UI); the
             zone editor (menu/edit_dns_zone).
    Notes:   a CNAME that gives a TSIG key a right (tsig_record_notice, 2.1.4.14) is audited naming the key.
             Only CNAME-vs-CNAME clashes are refused here; a CNAME beside other records of the same name is not checked.
    """
    if rtype not in RECORD_TYPES:
        raise ValidationError("unsupported record type")
    record = validate_record(rtype, form)
    with vars_lock():
        data = load_vars()
        zone = (data.get("dns") or {}).get(key)
        if zone is None:
            raise ValidationError("unknown zone")
        record = record_vlan(key, rtype, record, form, zone, dns_filter=data.get("dns_filter"))   # 2.1.4.16
        existing = zone.setdefault(rtype, [])
        if rtype == "CNAME" and any(r.get("name") == record["name"] and r.get("vlan") == record.get("vlan")
                                    for r in existing):
            raise ValidationError("a CNAME with that name already exists")
        keys = tsig_record_notice(data, key, rtype, record)     # before the record is in the zone
        existing.append(record)
        save_vars(data)
    # a new alias of a record a TSIG key holds with its aliases widens that key (2.1.4.14): the audit names it
    write_audit(actor, "DNS_ADD", f"zone={key} {rtype} {record}"
                + (f" tsig={','.join(keys)} may update its _acme-challenge" if keys else ""), source)
    return record
