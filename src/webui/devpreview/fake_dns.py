import base64
import os
import re

from webui.devpreview.fabric_rules import PRIVATE_TLDS, ValidationError
from webui.devpreview.sample_data import RECORD_TYPES, SAMPLE_FABRIC_NAMES

ZONE_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def _tsig(state, name, zone, created):
    """Purpose: A throwaway TSIG secret and its RFC2136 settings, as the agent answers a new key or a new secret.
    Inputs:  state — DevState; name — the key; zone — its zone's name; created — True for a new key.
    Returns: {"key": {"name"}, "secret", "ini"}.
    Fails:   never.
    Feeds:   fake_dns."""
    secret = base64.b64encode(os.urandom(32)).decode()
    ini = (f"# RFC2136 credentials for TSIG key: {name}\ndns_rfc2136_server = 192.168.1.53\n"
           f"dns_rfc2136_port = 53\ndns_rfc2136_name = {name}\ndns_rfc2136_secret = {secret}\n"
           f"dns_rfc2136_algorithm = HMAC-SHA256\ndns_rfc2136_base_domain = {zone or 'home.arpa'}\n")
    state.log("TSIG_ADD" if created else "TSIG_SECRET", f"key={name} (in memory)")
    return {"key": {"name": name}, "secret": secret, "ini": ini}


def _value(body):
    """Purpose: A record's value from the console's fields (2.1.2.22): value; priority for MX, priority, weight and
             port for SRV — what the agent checks for each type.
    Inputs:  body — dict: type, value (or ip, target, text), priority, weight, port.
    Returns: the value str.
    Fails:   ValidationError "<field> must be a number", or "type, name and a value are required".
    Feeds:   fake_dns."""
    value = next((str(body.get(f, "")).strip() for f in ("value", "ip", "target", "text")
                  if str(body.get(f, "")).strip()), "")
    nums = {f: str(body.get(f, "")).strip() for f in ("priority", "weight", "port")}
    need = {"MX": ("priority",), "SRV": ("priority", "weight", "port")}.get(body.get("type"), ())
    bad = next((f for f in need if not nums[f].isdigit()), "")
    if bad:
        raise ValidationError(f"{bad} must be a number")
    if not value or not str(body.get("name", "")).strip():
        raise ValidationError("type, name and a value are required")
    return " ".join([nums[f] for f in need] + [value])


def _record(state, key, op, body):
    """Purpose: A zone's record added, deleted or linked from the landing page (manual 1.4.2.4), in memory, refused
             as the agent refuses (fabric's own names; a stale record; a type or name that cannot be linked; a bad
             port).
    Inputs:  state — DevState; key — the zone; op — "records", "records/delete" or "records/link"; body — dict.
    Returns: the answer ({"name"} for an add, else {}).
    Fails:   ValidationError with the agent's reason.
    Feeds:   fake_dns."""
    zone = state.data["zones"][key]
    records = zone["records"]
    rtype, name = body.get("type", ""), str(body.get("name", "")).strip()
    if op == "records":
        if rtype not in RECORD_TYPES:
            raise ValidationError("pick a record type")
        records.append((rtype, name, _value(body)))
        state.log("DNS_ADD", f"zone={key} {rtype} {name} (in memory)")
        return {"name": name}
    idx = int(body.get("index", -1))
    if not rtype or idx < 0:
        raise ValidationError("pick a record to link")
    if idx >= len(records) or records[idx][:2] != (rtype, name):
        raise ValidationError("record changed since it was shown; reload and try again")
    if op == "records/delete":
        own = SAMPLE_FABRIC_NAMES.get((rtype, name)) if key == "dynamic_zone_var" else None
        if own:
            raise ValidationError(f"{'home.arpa' if name == '@' else name + '.home.arpa'} is provided by fabric "
                                  f"({own[0]}, from the setting {own[1]}): every apply adds it back, so it cannot be "
                                  "deleted here")
        records.pop(idx)
        state.log("DNS_DELETE", f"zone={key} {rtype} {name} (in memory)")
        return {}
    port = str(body.get("link_port", "")).strip()
    if rtype not in ("A", "AAAA", "CNAME"):
        raise ValidationError("only A, AAAA and CNAME records can be linked")
    if "*" in name:
        raise ValidationError("a wildcard name cannot be linked")
    if body.get("link") and port and not (port.isdigit() and 1 <= int(port) <= 65535):
        raise ValidationError("link port must be between 1 and 65535")
    links = zone.setdefault("links", {})
    if body.get("link"):
        links[f"{rtype}|{name}"] = {"label": str(body.get("link_label", "")).strip() or None,
                                    "port": int(port) if port else None, "path": body.get("link_path") or None}
    else:
        links.pop(f"{rtype}|{name}", None)
    state.log("DNS_LINK" if body.get("link") else "DNS_UNLINK", f"{rtype} {name} (in memory)")
    return {}


def fake_dns(state, who, route, body):
    """Purpose: The fake agent's DNS changes: zones, records, the landing page's links, TSIG keys — in memory.
    Inputs:  state — DevState; who — the preview's person; route — segments after /v1/; body — dict.
    Returns: the agent's answer, or None for a route that is not DNS.
    Fails:   ValidationError with the agent's reasons (a zone's name, an existing zone, a public name without the
             tick, the site's own zone, a wrong confirmation, a record's fields).
    Feeds:   fake_agent."""
    zones = state.data["zones"]
    if route == ["zones"]:
        name = str(body.get("name", "")).strip().rstrip(".").lower()
        public = not (name == "home.arpa" or name.endswith(".home.arpa") or name.rsplit(".", 1)[-1] in PRIVATE_TLDS)
        err = ("not a DNS name of at least two labels" if not ZONE_RE.match(name) else
               "it is already a zone" if any(z["name"] == name for z in zones.values()) else
               "a public name needs 'Hide the public name' ticked" if public and not body.get("hide_public") else "")
        if err:
            raise ValidationError(f"{name or 'the name'}: {err}")
        zones[name] = {"name": name, "records": []}
        state.log("DNS_ZONE_ADD", f"zone={name} (in memory)")
        return {"key": name, "name": name}
    if len(route) >= 3 and route[0] == "zones" and route[1] in zones:
        key, op = route[1], "/".join(route[2:])
        if op == "delete":
            if key == "dynamic_zone_var":
                raise ValidationError("the site's own zone cannot be removed")
            if str(body.get("confirm", "")).strip().rstrip(".").lower() != zones[key]["name"]:
                raise ValidationError(f"type the zone's name, {zones[key]['name']}, to remove it")
            gone = zones.pop(key)
            state.log("DNS_ZONE_DELETE", f"zone={key} records={len(gone['records'])} (in memory)")
            return {"name": gone["name"], "records": len(gone["records"])}
        if op in ("records", "records/delete", "records/link"):
            return _record(state, key, op, body)
    if route == ["tsig"]:
        name = str(body.get("name", "")).strip() or "preview"
        state.data["tsig"].append({"name": name, "algorithm": "hmac-sha256", "types": "TXT",
                                   "scope": f"(dev preview) {body.get('scope', '')}", "acls": []})
        return _tsig(state, name, body.get("zone"), True)
    if len(route) == 3 and route[0] == "tsig" and route[2] == "rotate":
        return _tsig(state, route[1], "", False)
    if len(route) == 3 and route[0] == "tsig" and route[2] == "delete":
        state.data["tsig"] = [k for k in state.data["tsig"] if k["name"] != route[1]]
        return {}
    return None
