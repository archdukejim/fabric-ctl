from fabriclib.common.errors import ValidationError
from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.dns.split.split_needs_filter import WHY
from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.common.vlan_refs import parse_vlan_ref, vlan_ref


def record_vlan(key, rtype, record, form, zone, index=None, plan=None, dns_filter="bind"):
    """Purpose: the VLAN a record answers alone, as typed, checked (decision 2.1.4.16, manual 1.4.1.11): a VLAN of
             the site's plan, in one of the site's own forward zones, and never a CNAME beside another record of the
             same name for the same VLAN (or another record beside such a CNAME), and only with the DNS filter on
             (split_needs_filter, 2.1.4.16).
    Inputs:  key — the zone's key in `dns:`; rtype — the record's type; record — validate_record's fields; form —
             the typed fields (vlan: "", "20" or "20@branch"); zone — the zone's records ({type: [record]}); index —
             the record's place in its type's list when it is being replaced (left out of the checks), else None;
             plan — the site's plan (default: the copy this site last read); dns_filter — the site's setting
             (bind or none; unset counts as bind).
    Returns: record, with "vlan" (the VLAN's reference) when one was given.
    Fails:   ValidationError: the DNS filter off; a VLAN that is not one; one the site's plan does not have; a VLAN
             in a reverse zone;
             a CNAME clash for that VLAN.
    Feeds:   add_record, update_record."""
    text = str(form.get("vlan") or "").strip()
    if not text:
        return record
    if str(dns_filter or "bind").strip().lower() != "bind":
        raise ValidationError(WHY)
    if str(key).endswith(".arpa"):
        raise ValidationError("a reverse zone answers everyone: a record for one VLAN goes in a forward zone")
    ref = vlan_ref(dict(zip(("id", "location"), parse_vlan_ref(text))))
    plan = load_plan_cache() if plan is None else plan
    known = [vlan_ref(x) for x in (plan or {}).get("vlans") or []]
    if ref not in known:
        raise ValidationError(f"VLAN {ref} is not in the site's plan (it has {', '.join(known) or 'none yet'})")
    same = [t for t in RECORD_TYPES for i, r in enumerate(zone.get(t) or [])
            if r.get("name") == record["name"] and str(r.get("vlan") or "") == ref and not (t == rtype and i == index)]
    if same and (rtype == "CNAME" or "CNAME" in same):
        raise ValidationError(f"{record['name']} for VLAN {ref}: a CNAME cannot sit beside another record of the same "
                              "name")
    return {**record, "vlan": ref}
