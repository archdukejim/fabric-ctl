import base64
import os
import re
import urllib.parse

from webui import views
from webui.devpreview.fabric_rules import PRIVATE_TLDS
from webui.devpreview.sample_data import RECORD_TYPES, SAMPLE_FABRIC_NAMES

ZONE_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def _zones(h, parts, form):
    """Purpose: a zone added or removed in memory, refused as fabric refuses it where the preview can tell (the
             name's form, an existing zone, a public name without the tick, the site's own zone, a wrong
             confirmation).
    Inputs:  h — the dev handler (send, state); parts — segments after /bind9/zones/: ['new'] or [<key>, 'remove'];
             form — dict (name, hide_public; confirm).
    Returns: True (a 303 with msg or err was sent, or a 404).
    Fails:   never.
    Feeds:   dev_post_dns."""
    zones = h.state.data["zones"]
    if parts == ["new"]:
        name = form.get("name", "").strip().rstrip(".").lower()
        public = not (name == "home.arpa" or name.endswith(".home.arpa") or name.rsplit(".", 1)[-1] in PRIVATE_TLDS)
        err = ("not a DNS name of at least two labels" if not ZONE_RE.match(name) else
               "it is already a zone" if any(z["name"] == name for z in zones.values()) else
               "a public name needs 'Hide the public name' ticked" if public and not form.get("hide_public") else "")
        if err:
            h.send(303, b"", location="/bind9?err=" + urllib.parse.quote(f"{name or 'the name'}: {err}"))
            return True
        zones[name] = {"name": name, "records": []}
        h.state.log("DNS_ZONE_ADD", f"zone={name} (in memory)")
        h.send(303, b"", location=f"/bind9?zone={urllib.parse.quote(name)}&msg=" +
               urllib.parse.quote(f"Zone {name} added (dev preview: in memory only)."))
        return True
    if len(parts) == 2 and parts[1] == "remove" and parts[0] in zones:
        key, back = parts[0], f"/bind9?zone={urllib.parse.quote(parts[0])}"
        if key == "dynamic_zone_var" or form.get("confirm", "").strip().rstrip(".").lower() != zones[key]["name"]:
            h.send(303, b"", location=back + "&err=" + urllib.parse.quote(
                "the site's own zone cannot be removed" if key == "dynamic_zone_var"
                else f"type the zone's name, {zones[key]['name']}, to remove it"))
            return True
        gone = zones.pop(key)
        h.state.log("DNS_ZONE_DELETE", f"zone={key} records={len(gone['records'])} (in memory)")
        h.send(303, b"", location="/bind9?msg=" + urllib.parse.quote(
            f"Zone {gone['name']} removed with its {len(gone['records'])} record(s) (dev preview: in memory only)."))
        return True
    h.send(404, views.error_page(404, "Not found."))
    return True


def _landing(h, op, form):
    """Purpose: the landing page's links acted out in memory (manual 1.4.2.4): link a record of the site's zone, or stop
             linking it, refused as fabric-agent refuses (no record picked, another type, a wildcard, a stale record,
             a bad port).
    Inputs:  h — the dev handler (send, state); op — "add" (form record "<type>|<index>|<name>", link_label,
             link_port, link_path) or "remove" (form type, index, name); form — dict.
    Returns: True (a 303 to /bind9?view=landing with msg or err, or a 404).
    Fails:   never.
    Feeds:   dev_post_dns."""
    zone = h.state.data["zones"]["dynamic_zone_var"]
    if op == "add":
        rtype, _, rest = form.get("record", "").partition("|")
        index, _, name = rest.partition("|")
    elif op == "remove":
        rtype, index, name = form.get("type", ""), form.get("index", ""), form.get("name", "")
    else:
        h.send(404, views.error_page(404, "Not found."))
        return True
    idx = int(index) if index.isdigit() else -1
    port = form.get("link_port", "").strip()
    err = ("pick a record to link" if not rtype or idx < 0 else
           "record changed since it was shown; reload and try again"
           if idx >= len(zone["records"]) or zone["records"][idx][:2] != (rtype, name) else
           "only A, AAAA and CNAME records can be linked" if rtype not in ("A", "AAAA", "CNAME") else
           "a wildcard name cannot be linked" if "*" in name else
           "link port must be between 1 and 65535" if op == "add" and port and not (
               port.isdigit() and 1 <= int(port) <= 65535) else "")
    if err:
        h.send(303, b"", location="/bind9?view=landing&err=" + urllib.parse.quote(err))
        return True
    links = zone.setdefault("links", {})
    if op == "add":
        links[f"{rtype}|{name}"] = {"label": form.get("link_label", "").strip() or None,
                                    "port": int(port) if port else None, "path": form.get("link_path") or None}
        msg = f"{name} is linked from the landing page (dev preview: in memory only)."
    else:
        links.pop(f"{rtype}|{name}", None)
        msg = f"{name} is no longer linked from the landing page (dev preview: in memory only)."
    h.state.log("DNS_LINK" if op == "add" else "DNS_UNLINK", f"{rtype} {name} (in memory)")
    h.send(303, b"", location="/bind9?view=landing&msg=" + urllib.parse.quote(msg))
    return True


def _value(form):
    """Purpose: the in-memory record's value from the console's form (2.1.2.22): type, name, value; priority for MX,
             priority, weight and port for SRV — the fields fabric-agent checks for each type.
    Inputs:  form — dict: type, value (or the older ip, target, text), priority, weight, port.
    Returns: (value str, "") or ("", why it is refused).
    Fails:   never.
    Feeds:   dev_post_dns."""
    rtype = form.get("type", "")
    value = next((form.get(f, "").strip() for f in ("value", "ip", "target", "text") if form.get(f, "").strip()), "")
    nums = {f: form.get(f, "").strip() for f in ("priority", "weight", "port")}
    need = {"MX": ("priority",), "SRV": ("priority", "weight", "port")}.get(rtype, ())
    bad = next((f for f in need if not nums[f].isdigit()), "")
    if bad:
        return "", f"{bad} must be a number"
    return " ".join([nums[f] for f in need] + [value]), ""


def dev_post_dns(h, path, form):
    """Purpose: TSIG keys, zones and zone records acted out in memory (secrets are fresh random throwaways).
    Inputs:  h — the dev handler (send, state, ctx); path — /bind9/tsig/create, /bind9/tsig/<name>/rotate|delete,
             /bind9/zones/new, /bind9/zones/<key>/remove, /bind9/zone/<key>/add|delete, /bind9/landing/add|remove;
             form — dict.
    Returns: True when the path was handled; None otherwise.
    Fails:   ValueError for a non-numeric record index; IndexError for an unexpected …/rotate path (not caught).
    Feeds:   dev_post_action."""
    state = h.state
    if path == "/bind9/tsig/create" or path.endswith("/rotate"):
        name = form.get("name", "") if path.endswith("create") else path.split("/")[3]
        secret = base64.b64encode(os.urandom(32)).decode()
        ini = (f"# RFC2136 credentials for TSIG key: {name}\ndns_rfc2136_server = 192.168.1.53\n"
               f"dns_rfc2136_port = 53\ndns_rfc2136_name = {name}\ndns_rfc2136_secret = {secret}\n"
               f"dns_rfc2136_algorithm = HMAC-SHA256\ndns_rfc2136_base_domain = {form.get('zone') or 'home.arpa'}\n")
        if path.endswith("create") and name:
            state.data["tsig"].append({"name": name, "algorithm": "hmac-sha256", "types": "TXT",
                                       "scope": f"(dev preview) {form.get('scope', '')}", "acls": []})
        state.log("TSIG_ADD" if path.endswith("create") else "TSIG_SECRET", f"key={name} (in memory)")
        h.send(200, views.tsig_result(h.ctx, name or "preview", secret, ini,
                                      "created" if path.endswith("create") else "rotated"))
        return True
    if path.startswith("/bind9/tsig/") and path.endswith("/delete"):
        name = path.split("/")[3]
        state.data["tsig"] = [k for k in state.data["tsig"] if k["name"] != name]
        h.send(303, b"", location="/bind9?view=tsig&msg=" +
               urllib.parse.quote(f"TSIG key {name} removed (dev preview: in memory)."))
        return True
    if path.startswith("/bind9/zones/"):
        return _zones(h, [urllib.parse.unquote(p) for p in path.split("/")[3:]], form)
    if path.startswith("/bind9/landing/"):
        return _landing(h, path[len("/bind9/landing/"):], form)
    parts = path.strip("/").split("/")
    if not (len(parts) == 4 and parts[:2] == ["bind9", "zone"] and parts[2] in state.data["zones"]):
        return None
    key, op = parts[2], parts[3]
    records = state.data["zones"][key]["records"]
    if op == "add":
        rtype, name = form.get("type", ""), form.get("name", "").strip()
        value, why = _value(form)
        if rtype not in RECORD_TYPES or not name or not value.split(" ")[-1] or why:
            h.send(303, b"", location=f"/bind9?zone={urllib.parse.quote(key)}&err=" +
                   urllib.parse.quote(why or "type, name and a value are required"))
            return True
        records.append((rtype, name, value))
        state.log("DNS_ADD", f"zone={key} {rtype} {name} {value} (in memory)")
        msg = "Record added (dev preview: in memory only)."
    elif op == "delete":
        idx = int(form.get("index", -1))           # position in the zone's list (DevState.zone)
        own = SAMPLE_FABRIC_NAMES.get((form.get("type"), form.get("name"))) if key == "dynamic_zone_var" else None
        if own:                                    # fabric-agent refuses fabric's own names (2.1.2.22)
            name = form.get("name")
            h.send(303, b"", location=f"/bind9?zone={urllib.parse.quote(key)}&err=" + urllib.parse.quote(
                f"{'home.arpa' if name == '@' else name + '.home.arpa'} is provided by fabric ({own[0]}, from the "
                f"setting {own[1]}): every apply adds it back, so it cannot be deleted here"))
            return True
        if 0 <= idx < len(records) and records[idx][0] == form.get("type"):
            removed = records.pop(idx)
            state.log("DNS_DELETE", f"zone={key} {removed[0]} {removed[1]} (in memory)")
        msg = "Record deleted (dev preview: in memory only)."
    else:
        h.send(404, views.error_page(404, "Not found."))
        return True
    h.send(303, b"", location=f"/bind9?zone={urllib.parse.quote(key)}&msg=" + urllib.parse.quote(msg))
    return True
