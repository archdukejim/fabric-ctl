import copy

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns.common.fabric_record import fabric_record
from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.dns.drop_removed_names import drop_removed_names
from fabriclib.dns.split.own_in_split import own_in_split
from fabriclib.dns.split.split_home import split_home
from fabriclib.dns.tsig_record_notice import tsig_record_notice
from fabriclib.dns.validate_record import validate_record

# what a record keeps through an edit that the edit row does not ask for (the landing page's link, 2.1.2.22)
KEPT = ("link",)


def update_record(actor, key, rtype, index, expected_name, form, source="cli", split=None):
    """Purpose: One record of a zone replaced in place (decision 2.1.4.15, manual 1.4.1.10): the replacement checked
             as an add is, then the old record and the new written in one save, so a refused replacement leaves the
             old record as it was. Run apply afterwards.
    Inputs:  actor — str, who asks (audit); key — the zone's key in `dns:`; rtype — the record's type (fixed: an edit
             never changes it); index — int, its place in that type's list; expected_name — the name the caller
             showed (a stale view cannot change another record); form — the new fields as validate_record takes
             them (name, value or the type's own field, priority, weight, port); source — "cli" or "web";
             split — the tab (decision 2.1.4.18): a split's index, or None for All networks.
    Returns: {"old": the record before, "new": the record after}. The landing page's link stays with the record;
             an ACME (DNS-01) key granted the old name loses it when no record of the zone keeps it
             (drop_removed_names, 2.1.4.12); a CNAME that gives a TSIG key a right is audited naming it (2.1.4.14).
    Fails:   ValidationError "unsupported record type"; "record changed since it was shown; reload and try again"
             (unknown zone or type, index out of range, another name); "<name> is provided by fabric (…)" for one
             of fabric's own names (or, in a split, own_in_split's); "a CNAME with that name already exists";
             "nothing to change"; split_home's (a stale split); validate_record's;
             OSError or yaml.YAMLError from vars_lock, load_vars, save_vars, write_audit.
    Feeds:   agent route POST /v1/zones/<key>/records/update (fabric-agent, src/agent/post_dns)."""
    if rtype not in RECORD_TYPES:
        raise ValidationError("unsupported record type")
    new = validate_record(rtype, form)
    with vars_lock():
        data = load_vars()
        zone = (data.get("dns") or {}).get(key)
        if zone is None:
            raise ValidationError("record changed since it was shown; reload and try again")
        home = split_home(zone, split)                          # the tab: the zone, or a split (2.1.4.18)
        records = home.get(rtype) or []
        if not 0 <= index < len(records) or (records[index].get("name") or "") != expected_name:
            raise ValidationError("record changed since it was shown; reload and try again")
        old = records[index]
        own = fabric_record(data, key, rtype, old) if home is zone else None
        if own:
            fqdn = data.get("domain") if expected_name == "@" else f"{expected_name}.{data.get('domain')}"
            raise ValidationError(f"{fqdn} is provided by fabric ({own['service']}, from the setting "
                                  f"{own['setting']}): every apply adds it back, so it cannot be changed here")
        if home is not zone:
            own_in_split(data, key, new["name"])
        new = {**new, **{k: old[k] for k in KEPT if k in old and k not in new}}
        if new == old:
            raise ValidationError("nothing to change: the record is already so")
        if rtype == "CNAME" and any(r.get("name") == new["name"] for i, r in enumerate(records) if i != index):
            raise ValidationError("a CNAME with that name already exists")
        before = copy.deepcopy(data)
        keys = tsig_record_notice(data, key, rtype, new) if home is zone else []
        records[index] = new
        dropped = drop_removed_names(before, data, key) if new["name"] != old.get("name") and home is zone else []
        save_vars(data)
    write_audit(actor, "DNS_UPDATE", f"zone={key}" + (f" split={split}" if home is not zone else "")
                + f" {rtype} {old} -> {new}"
                + (f" tsig={','.join(keys)} may update its _acme-challenge" if keys else ""), source)
    for kname, names in dropped:
        write_audit(actor, "TSIG_UPDATE", f"key={kname} dropped {', '.join(names)}: the record was renamed", source)
    return {"old": old, "new": new}
