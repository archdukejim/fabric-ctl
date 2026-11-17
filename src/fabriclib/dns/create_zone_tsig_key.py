from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.dns.acme_picks import acme_picks
from fabriclib.dns.add_tsig_key import add_tsig_key
from fabriclib.dns.list_zones import list_zones
from fabriclib.dns.rfc2136_settings import rfc2136_settings

# scope -> what the key may change in its zone
SCOPES = {
    "acme": "ACME (DNS-01): TXT at _acme-challenge.<record> for records of the zone you pick (2.1.4.12)",
    "acme-hosts": "TXT at _acme-challenge.<host> for the listed hosts only (certbot DNS-01)",
    "acme-zone": "TXT at any _acme-challenge name in the zone (certbot DNS-01)",
    "any-name": "the chosen record types at any name in the zone",
}
ANY_NAME_TYPES = ("A", "AAAA", "CNAME", "TXT", "SRV", "MX")


def create_zone_tsig_key(actor, name, zone, scope, hosts=(), types=("TXT",), secret=None, source="web",
                         with_aliases=()):
    """Purpose: The web UI's "new TSIG key for a zone": a key limited to one of fabric's forward zones and one scope,
             deny-by-default otherwise. Run apply afterwards.
    Inputs:  actor — str, who asks (audit).
             name — str key name (stripped; validated by normalize_tsig_keys).
             zone — str, a forward zone name from list_zones (reverse zones are refused).
             scope — "acme" (ACME (DNS-01) mode, 2.1.4.12: `hosts` and `with_aliases` picked from the zone's
             records), or Custom's: "acme-hosts" (TXT at _acme-challenge.<host> for `hosts` only), "acme-zone"
             (TXT at any _acme-challenge name; sets primary) or "any-name" (`types` at any name in the zone).
             hosts — iterable of str for acme and acme-hosts (blank ones dropped).
             types — iterable of str from ANY_NAME_TYPES for any-name; default ("TXT",).
             secret — base64 str to keep an existing client's key working; None or blank for a new one.
             source — default "web". Reads vars.yaml.
             with_aliases — iterable of str for acme: A or AAAA records granted with every alias pointing at them,
             as the zone is at each render (records_with_aliases, 2.1.4.14).
    Returns: (entry, secret, rfc2136_ini_text): the stored key dict, its base64 secret and the rfc2136.ini text for its
             client.
    Fails:   ValidationError "… is not one of this fabric's forward zones", "list at least one host that may prove its
             name", acme's refusals (acme_picks: a name not a record of the zone, a record with aliases not an A or
             AAAA), "record types must be among …", "unknown scope", or one from add_tsig_key.
    Feeds:   agent route POST /v1/tsig (fabric-agent, src/agent/, called by the web UI); tests/pki/run.py.
    Notes:   the rfc2136.ini path is always fabric's default: a web caller can never choose `out`.
    """
    forward = {z["name"] for z in list_zones() if not z["reverse"]}
    if zone not in forward:
        raise ValidationError(f"{zone!r} is not one of this fabric's forward zones")
    entry = {"name": str(name).strip(), "domain": zone, "record_types": ["TXT"]}
    if scope == "acme":
        entry.update(acme_picks(load_vars(), zone, hosts, with_aliases))
    elif scope == "acme-hosts":
        entry["records"] = [h.strip() for h in hosts if h.strip()]
        if not entry["records"]:
            raise ValidationError("list at least one host that may prove its name")
    elif scope == "acme-zone":
        entry["primary"] = True
    elif scope == "any-name":
        types = [t for t in types if t]
        if not types or any(t not in ANY_NAME_TYPES for t in types):
            raise ValidationError(f"record types must be among {', '.join(ANY_NAME_TYPES)}")
        entry.update(any_name=True, record_types=types)
    else:
        raise ValidationError("unknown scope")
    key, secret = add_tsig_key(actor, entry, (secret or "").strip() or None, source=source)
    return key, secret, rfc2136_settings(load_vars(), key, secret)
