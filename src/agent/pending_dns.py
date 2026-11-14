import yaml

from fabriclib.common.load_vars import load_vars
from fabriclib.dns.tsig_record_notice import tsig_record_notice


def _zone(key):
    """Purpose: A zone key as people read it: the site's zone for dynamic_zone_var, else its name.
    Inputs:  key — str.
    Returns: str.
    Fails:   never.
    Feeds:   describe_dns."""
    return "the site's zone" if key == "dynamic_zone_var" else key


def _widens(key, rtype, body):
    """Purpose: The Review row's notice when a new CNAME gives a TSIG key a right (2.1.4.14, manual 1.4.1.9.4).
    Inputs:  key — the zone's key; rtype — the record's type; body — the change's body (name, value or target).
    Returns: " — TSIG key npm may update this name's _acme-challenge", or "".
    Fails:   never (the settings unreadable: no notice).
    Feeds:   describe_dns."""
    if rtype != "CNAME":
        return ""
    try:
        keys = tsig_record_notice(load_vars(), key, rtype, body)
    except (OSError, yaml.YAMLError):
        return ""
    return (f" — TSIG key{'s' if len(keys) > 1 else ''} {', '.join(keys)} may update this name's _acme-challenge"
            if keys else "")


def describe_dns(route, body):
    """Purpose: A DNS change in a sentence ("Add A record www to home.lan", "Remove TSIG key npm", "Change TSIG key
             npm: add web, remove nas").
    Inputs:  route — segments after /v1/ (zones/..., tsig/<name>/delete, tsig/<name>/update); body — the change's
             body.
    Returns: str.
    Fails:   never.
    Feeds:   agent/pending_thing.describe_change."""
    if route[0] == "tsig" and route[2:] == ["update"]:          # Edit names (2.1.4.13, manual 1.4.1.9.2)
        def names(field):
            value = body.get(field)
            return [str(v) for v in value] if isinstance(value, list) else []
        parts = ([f"add {n}" for n in names("add")] + [f"remove {n}" for n in names("drop")]
                 + [f"add {n} and its aliases" for n in names("add_with_aliases")]
                 + [f"remove {n} and its aliases" for n in names("drop_with_aliases")]
                 + ([f"scope {body['scope']}"] if isinstance(body.get("scope"), str) and body["scope"] else [])
                 + ([f"types {' '.join(names('record_types'))}"] if names("record_types") else []))
        return f"Change TSIG key {route[1]}: {', '.join(parts) or 'nothing'}"
    if route[0] == "tsig":
        return f"Remove TSIG key {route[1]}"
    if len(route) == 1:
        return f"Add zone {body.get('name', '')}".strip()
    zone, rtype, name = _zone(route[1]), body.get("type", ""), body.get("name", "")
    if route[2:] == ["delete"]:
        return f"Remove zone {zone} with its records"
    if route[2:] == ["records"]:
        return f"Add {rtype} record {name} to {zone}" + _widens(route[1], rtype, body)
    if route[3:] == ["delete"]:
        return f"Delete {rtype} record {name} from {zone}"
    if route[3:] == ["update"]:                                 # a record replaced in place (2.1.4.15)
        old = body.get("old_name", "")
        value = body.get("value", "")
        return (f"Change {rtype} record {old} in {zone}" + (f" to {name}" if name and name != old else "")
                + (f": {value}" if value else "") + _widens(route[1], rtype, body))
    if body.get("link") == "on":
        return f"Link {name} from the landing page"
    return f"Stop linking {name} from the landing page"
