from webui.devpreview.fabric_rules import ValidationError
from webui.devpreview.sample_data import SAMPLE_DHCP, SAMPLE_DNS_FILTER, SAMPLE_QUERY_LOG, SAMPLE_RADIUS

APPLIED = {"applied": True, "output": "dev preview: nothing applied"}


def _options(body):
    """Purpose: Where a DHCP option goes in the sample: the global list, a subnet's or a client class's.
    Inputs:  body — the agent's body (subnet, class, mac).
    Returns: (list to change, what it is called).
    Fails:   never.
    Feeds:   _dhcp."""
    if body.get("subnet") and SAMPLE_DHCP["subnets"]:
        return SAMPLE_DHCP["subnets"][0].setdefault("options", []), f"subnet {body['subnet']}"
    for c in SAMPLE_DHCP["client_classes"]:
        if body.get("class") and c["name"] == body["class"]:
            return c.setdefault("options", []), f"class {c['name']}"
    return SAMPLE_DHCP["options"], "every subnet"


def _dhcp(route, body):
    """Purpose: DHCP's changes on the sample data in memory (nothing applied): on and off, reservations, subnets,
             options, client classes.
    Inputs:  route — segments after /v1/dhcp/; body — dict.
    Returns: the agent's answer (with applied), or None for another route.
    Fails:   never.
    Feeds:   fake_network."""
    subnets = SAMPLE_DHCP["subnets"]
    if route in (["on"], ["off"]):
        return {**APPLIED, "dhcp": {"subnets": [s["subnet"] for s in subnets], "interfaces": SAMPLE_DHCP["interfaces"]}}
    if route == ["reservations"]:
        r = {"mac": str(body.get("mac", "")).lower(), "ip": body.get("ip", ""), "hostname": body.get("hostname", "")}
        subnets[0]["reservations"].append(r)
        return {**APPLIED, "reservation": r}
    if len(route) == 3 and route[0] == "reservations":
        subnets[0]["reservations"][:] = [r for r in subnets[0]["reservations"] if r["mac"] != route[1]]
        return APPLIED
    if route == ["subnets"]:
        s = {"subnet": body.get("network", ""), "name": body.get("name", ""), "vlan": body.get("vlan") or None,
             "router": body.get("router", ""), "pools": body.get("pools") or [], "notes": body.get("notes", ""),
             "reservations": [], "options": []}
        subnets.append(s)
        return {**APPLIED, "subnet": s}
    if route == ["subnets", "update"]:
        s = next((x for x in subnets if x["subnet"] == body.get("subnet")), None)
        if s is None:
            raise ValidationError(f"no subnet {body.get('subnet')}")
        s.update({k: body[k] for k in ("name", "router", "notes") if body.get(k)})
        return {**APPLIED, "subnet": s}
    if route == ["subnets", "delete"]:
        subnets[:] = [s for s in subnets if s["subnet"] != body.get("subnet")] or subnets
        return {**APPLIED, "removed": body.get("subnet", "")}
    if route in (["options"], ["options", "delete"]):
        opts, where = _options(body)
        if route == ["options"]:
            opts.append({"name": body.get("option", ""), "data": body.get("data", "")})
        else:
            opts[:] = [o for o in opts if str(o.get("name", o.get("code"))) != body.get("option")]
        return {**APPLIED, "where": where}
    if route == ["classes"]:
        c = {"name": body.get("name", ""), "test": body.get("test", ""), "next_server": body.get("next_server", ""),
             "boot_file": body.get("boot_file", ""), "options": []}
        SAMPLE_DHCP["client_classes"].append(c)
        return {**APPLIED, "class": c}
    if len(route) == 3 and route[0] == "classes":
        SAMPLE_DHCP["client_classes"][:] = [c for c in SAMPLE_DHCP["client_classes"] if c["name"] != route[1]]
        return APPLIED
    return None


def _radius(route, body):
    """Purpose: 802.1X's RADIUS clients and password groups on the sample data in memory (nothing applied).
    Inputs:  route — segments after /v1/radius/; body — dict.
    Returns: the agent's answer, or None for another route.
    Fails:   never.
    Feeds:   fake_network."""
    clients, people = SAMPLE_RADIUS["clients"], SAMPLE_RADIUS["people"]
    if route == ["people"]:
        m = {"group": body.get("group", ""), "vlan": int(body["vlan"]) if str(body.get("vlan", "")).isdigit()
             else None, "priority": int(body["priority"]) if str(body.get("priority", "")).isdigit() else 100}
        people.append(m)
        return {**APPLIED, "mapping": m}
    if len(route) == 3 and route[0] == "people":
        people[:] = [m for m in people if m["group"] != route[1]]
        return APPLIED
    if route == ["clients"]:
        clients.append({"name": body.get("name", ""), "address": body.get("address", ""),
                        "message_authenticator": bool(body.get("message_authenticator"))})
        return {**APPLIED, "secret": "dev-preview-not-a-real-secret"}
    if len(route) == 3 and route[0] == "clients" and route[2] == "delete":
        clients[:] = [c for c in clients if c["name"] != route[1]]
        return APPLIED
    if len(route) == 3 and route[0] == "clients" and route[2] == "rotate":
        return {**APPLIED, "secret": "dev-preview-not-a-real-secret"}
    return None


def _filter(route, body):
    """Purpose: The DNS filter's changes on the sample data in memory (nothing fetched or applied), and the query log.
    Inputs:  route — segments after /v1/dns-filter/; body — dict (name, url, enabled, kind, upstreams, group,
             clients, on, youtube; the query log's client, name, blocked, limit).
    Returns: the agent's answer ({"result", "applied"}), or None for another route.
    Fails:   ValidationError for a client group that does not exist.
    Feeds:   fake_network."""
    d, what = SAMPLE_DNS_FILTER, "/".join(route)
    if what == "querylog":
        entries = [e for e in SAMPLE_QUERY_LOG["entries"] if not body.get("blocked") or e["blocked"]]
        return {"entries": entries}
    group = str(body.get("group", "")).strip()
    target = d if not group else next((g for g in d["groups"] if g["name"] == group), None)
    if target is None:
        raise ValidationError(f"no client group is called {group}")
    if what in ("lists", "lists/set"):
        url = str(body.get("url", "")).strip()
        row = next((r for r in d["lists"] if r["url"] == url), None)
        on, added = what == "lists" or body.get("enabled") == "on", row is None
        if row is None:
            row = {"id": "", "name": body.get("name") or url, "url": url, "description": "", "homepage": "",
                   "category": "Added by URL", "on_site": True, "enabled": on, "last_fetch": None,
                   "last_success": None, "rules": None, "memory_mb": None}
            d["lists"].append(row)
        row["on_site"], row["enabled"] = True, on
        return {"result": {"name": row["name"], "enabled": on, "added": added}, "applied": True}
    if what == "lists/delete":
        gone = next((r for r in d["lists"] if r["url"] == body.get("url")), {"name": body.get("url")})
        d["lists"] = [r for r in d["lists"] if r["url"] != body.get("url")]
        return {"result": {"name": gone["name"]}, "applied": True}
    if what == "fetch":
        return {"result": {}, "applied": True}
    if what in ("rules", "rules/delete"):
        kind, name = body.get("kind"), str(body.get("name", "")).strip().lower()
        own, other = (target["allow"], target["block"]) if kind == "allow" else (target["block"], target["allow"])
        if what == "rules":
            if name not in own:
                own.append(name)
            other[:] = [n for n in other if n != name]
        else:
            own[:] = [n for n in own if n != name]
        return {"result": {"name": name, "kind": kind, "group": group}, "applied": True}
    if what == "groups":
        name, clients = str(body.get("name", "")).strip().lower(), str(body.get("clients", "")).replace(",", " ")
        g = next((x for x in d["groups"] if x["name"] == name), None)
        if g:
            g["clients"] = clients.split()
        else:
            d["groups"].append({"name": name, "clients": clients.split(), "safe_search": False, "youtube": "strict",
                                "allow": [], "block": []})
        return {"result": {"name": name, "added": g is None, "clients": clients.split()}, "applied": True}
    if what == "groups/delete":
        d["groups"] = [x for x in d["groups"] if x["name"] != body.get("name")]
        return {"result": {"name": body.get("name")}, "applied": True}
    if what == "safe-search":
        on, youtube = body.get("on") == "on", body.get("youtube") or "strict"
        if group:
            target["safe_search"], target["youtube"] = on, youtube
        else:
            d["safe_search"] = {"on": on, "youtube": youtube}
        return {"result": {"on": on, "youtube": youtube, "group": group}, "applied": True}
    if what == "upstreams":
        pairs = [p.split() for p in str(body.get("upstreams", "")).replace("\n", ",").split(",") if p.strip()]
        d["upstreams"] = [{"address": p[0], "name": p[-1]} for p in pairs]
        return {"result": d["upstreams"], "applied": True}
    return None


def fake_network(state, who, route, body):
    """Purpose: The fake agent's network changes: DHCP, 802.1X and the DNS filter, on the sample data in memory.
    Inputs:  state — DevState; who — the preview's person; route — segments after /v1/; body — dict.
    Returns: the agent's answer, or None for another route.
    Fails:   ValidationError with the agent's reasons.
    Feeds:   fake_agent."""
    area = {"dhcp": _dhcp, "radius": _radius, "dns-filter": _filter}.get(route[0] if route else "")
    if area is None:
        return None
    answer = area(route[1:], body)
    if answer is not None:
        state.log(f"{route[0].upper()}_CHANGE", f"{'/'.join(route[1:])} (dev preview: in memory)")
    return answer
