from fabriclib.common.errors import ValidationError
from fabriclib.dns.record_aliases import record_aliases
from fabriclib.dns.zone_records_for import zone_records_for

CHOICE_TYPES = ("A", "AAAA", "CNAME")      # the names a certificate is for: hosts and their aliases


def key_record_choices(data, domain):
    """Purpose: The zone's existing records a TSIG key's names are chosen from (ACME (DNS-01) mode and Edit names,
             decisions 2.1.4.12 and 2.1.4.13): each A, AAAA or CNAME name once, and for an A or AAAA record the
             aliases a pick "with its aliases" grants now (2.1.4.14).
    Inputs:  data — the vars (domain, dns); domain — str, the zone's name.
    Returns: [{"name", "types" (e.g. ["A", "AAAA"]), "aliases" (sorted names; [] for a CNAME or a record without
             any), "address" (True for an A or AAAA name: it may be picked with its aliases)}], sorted by name. The
             zone's own name (@) and wildcards are left out: their challenge name is not `_acme-challenge.<name>`
             (a wildcard certificate is Custom's, 2.1.4.12).
    Fails:   ValidationError "… is not one of this fabric's zones".
    Feeds:   agent route GET /v1/tsig-choices/<zone>, edit_tsig_names, create_zone_tsig_key, ask_tsig_scope."""
    zone = zone_records_for(data, domain)
    if zone is None:
        raise ValidationError(f"{domain!r} is not one of this fabric's zones")
    types = {}
    for rtype in CHOICE_TYPES:
        for r in zone.get(rtype) or []:
            name = str(r.get("name") or "").lower() if isinstance(r, dict) else ""
            if name and name != "@" and not name.startswith("*"):
                types.setdefault(name, [])
                if rtype not in types[name]:
                    types[name].append(rtype)
    out = []
    for name in sorted(types):
        address = any(t in ("A", "AAAA") for t in types[name])
        out.append({"name": name, "types": types[name], "address": address,
                    "aliases": record_aliases(zone, domain, name) if address else []})
    return out
