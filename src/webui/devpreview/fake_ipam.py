import copy

from webui.devpreview.fabric_rules import (CATALOGUE, ValidationError, effective_options, export_plan, networks_view,
                                           settings_options, site_plan, suggest_split, suggest_subnet)
from webui.devpreview.sample_networks import (SAMPLE_NETWORK_LEASES, SAMPLE_NETWORK_READ, SAMPLE_NETWORK_VARS,
                                              SAMPLE_SCAN, SAMPLE_SCAN_REQUESTS, SAMPLE_SYNC)

HERE = SAMPLE_NETWORK_VARS["site_name"]
NOTHING = {"applied": None, "output": "dev preview: nothing written or applied", "warnings": []}


def network_read(state):
    """Purpose: The preview's plan, read_plan-shaped: a copy of the sample in this DevState, changed by the fake routes.
    Inputs:  state — DevState.
    Returns: dict.
    Fails:   never.
    Feeds:   fake_ipam, fake_pending (a held change's thing)."""
    return state.data.setdefault("networks", copy.deepcopy(SAMPLE_NETWORK_READ))


def _site(state, site):
    """Purpose: A site of the sample domain, refused as the agent refuses one that is not there (404, 2.1.8.21).
    Inputs:  state — DevState; site — str ("" or "-" this site).
    Returns: the site's name.
    Fails:   ValidationError "no such site: <s>".
    Feeds:   _read, fake_pending."""
    site = HERE if site in ("", "-") else site
    if site not in network_read(state)["plans"]:
        raise ValidationError(f"no such site: {site}")
    return site


def _overview(state, site):
    """Purpose: GET /v1/networks[/<site>] over the sample, drawn by fabriclib's own networks_view.
    Inputs:  state — DevState; site — str.
    Returns: networks_overview's dict.
    Fails:   ValidationError for a site not there.
    Feeds:   _read."""
    site, read = _site(state, site), network_read(state)
    sites = [{"name": s["name"], "own": s["name"] == HERE} for s in read["sites"]]
    out = networks_view(SAMPLE_NETWORK_VARS, read, site, sites, SAMPLE_NETWORK_LEASES if site == HERE else None)
    out.update(own=HERE, stale="", error="", leases_error="", scan_requests_error="",
               scan_requests=[] if site == HERE else SAMPLE_SCAN_REQUESTS, sync=SAMPLE_SYNC if site == HERE else None)
    return out


def _options(state, site, target):
    """Purpose: GET /v1/ipam/options/<site>[/<target>] over the sample, as options_overview shapes it.
    Inputs:  state — DevState; site — str; target — "", "site", "subnet:<name>" or "address:<ip>".
    Returns: options_overview's dict.
    Fails:   ValidationError for a site not there or a bad target.
    Feeds:   _read."""
    site = _site(state, site)
    plan = site_plan(network_read(state), site)
    settings = settings_options(SAMPLE_NETWORK_VARS) if site == HERE else None
    kind, _, name = target.partition(":")
    effective = None
    if target:
        if not (kind == "site" and not name) and not (kind in ("subnet", "address") and name):
            raise ValidationError("target: site, subnet:<name> or address:<ip>")
        effective = effective_options(plan, kind, name, SAMPLE_NETWORK_VARS if site == HERE else None, settings)
    subnets = [{"name": s["name"], "cidr": s["cidr"], "vlan": s.get("vlan"), "id": s.get("id"),
                "dhcp": bool(s.get("dhcp")), "options": s.get("options") or [], "netboot": s.get("netboot"),
                "reservations": [{"ip": a["ip"], "name": a.get("name", ""), "mac": a.get("mac", ""),
                                  "options": a.get("options") or [], "netboot": a.get("netboot")}
                                 for a in s.get("addresses") or [] if a["kind"] == "reservation"]}
               for s in plan["subnets"]]
    return {"site": site, "here": HERE, "domain": plan["domain_options"], "site_options": plan["site_options"],
            "settings": settings, "subnets": subnets,
            "catalogue": [{"code": c, "name": n} for c, n in sorted(CATALOGUE.items())], "effective": effective}


def _read(state, route):
    """Purpose: The address manager's reads (manual 1.10.4.35) over the sample.
    Inputs:  state — DevState; route — segments after /v1/.
    Returns: the answer, or None for another route.
    Fails:   ValidationError as the agent refuses.
    Feeds:   fake_ipam."""
    if route == ["networks"] or (len(route) == 2 and route[0] == "networks"):
        return _overview(state, route[1] if len(route) == 2 else "")
    if len(route) == 3 and route[0] == "networks" and route[2] == "export":
        site = _site(state, route[1])
        return {"csv": export_plan(network_read(state), site, SAMPLE_NETWORK_LEASES if site == HERE else None, HERE),
                "name": f"{site}-addresses.csv"}
    if len(route) in (3, 4) and route[:2] == ["ipam", "options"]:
        return _options(state, route[2], route[3] if len(route) == 4 else "")
    if route == ["ipam", "scan"]:
        subnets = [{"name": s["name"], "cidr": s["cidr"], "vlan": s.get("vlan"), "dhcp": s.get("dhcp"), "hosts": 254}
                   for s in network_read(state)["plans"][HERE]["subnets"]]
        no = state.toggles.get("noscan")
        return {"site": HERE, "subnets": subnets, "may": not no,
                "why": "no grant gives you networks scan at lan (manual 1.10.4.34)" if no else ""}
    return None


def _vlan_add(plan, site, block, body):
    """Purpose: Add VLAN on the sample plan, with the few refusals the preview shows.
    Inputs:  plan — the site's plan; site — str; block — the site's number; body — the change's body.
    Returns: the answer.
    Fails:   ValidationError for a bad or taken VLAN ID (at its location, manual 1.10.4.46), a location's VLAN
             with no subnet given.
    Feeds:   _change."""
    vid = str(body.get("id", ""))
    if not vid.isdigit() or not 1 <= int(vid) <= 4094:
        raise ValidationError(f"VLAN ID {vid!r} is a number from 1 to 4094")
    where = str(body.get("location", "")).strip().lower()
    if any(v["id"] == int(vid) and (v.get("location") or "") == where for v in plan["vlans"]):
        raise ValidationError(f"VLAN {vid}" + (f" at {where}" if where else "") + f" is already in {site}'s plan")
    if where and not body.get("subnet") and body.get("no_subnet") != "on":
        raise ValidationError("give --subnet: a location's VLAN has no suggested network")
    name = str(body.get("name", "")).strip().lower() or f"vlan{vid}"
    plan["vlans"].append({"id": int(vid), "location": where, "name": name, "purpose": body.get("purpose", ""),
                          "access": body.get("access", "full"), "notes": body.get("notes", "")})
    cidr = body.get("subnet") or suggest_subnet(block, int(vid))
    if body.get("no_subnet") != "on" and cidr:
        split = suggest_split(cidr) if body.get("split", "on") == "on" else {"gateway": "", "ranges": []}
        plan["subnets"].append({"name": f"{where}-{name}" if where else name, "cidr": cidr, "vlan": int(vid),
                                "location": where, "kind": "dhcp",
                                "gateway": body.get("gateway") or split.get("gateway", ""), "dhcp": True, "id": None,
                                "relay": "", "notes": "", "allow_overlap": "", "options": [],
                                "ranges": split.get("ranges") or [], "addresses": []})
    plan["vlans"].sort(key=lambda v: (v.get("location") or "", v["id"]))
    return {**NOTHING, "result": {"id": int(vid), "name": name}, "site": site, "own": site == HERE}


def _change(state, route, body):
    """Purpose: A change to a site's plan on the sample, in memory: the number, a VLAN added or removed, an address
             recorded or removed, a scan's find recorded; the others answer done with nothing changed.
    Inputs:  state — DevState; route — segments after /v1/; body — dict.
    Returns: the answer.
    Fails:   ValidationError as the agent refuses (a site not there, a bad number or VLAN, an address taken).
    Feeds:   fake_ipam."""
    read = network_read(state)
    site = HERE if route[:2] == ["ipam", "scan"] else _site(state, route[1])
    plan, rest = read["plans"][site], (["addresses"] if route[:2] == ["ipam", "scan"] else route[2:])
    record = next(s for s in read["sites"] if s["name"] == site)
    if rest == ["block"]:
        number = str(body.get("number", ""))
        if not number.isdigit() or not 1 <= int(number) <= 255:
            raise ValidationError(f"site number {number!r}: a whole number from 1 to 255")
        record["block"] = int(number)
    elif rest == ["vlans"]:
        return _vlan_add(plan, site, record.get("block"), body)
    elif len(rest) == 3 and rest[0] == "vlans" and rest[2] == "delete":
        def ref(x, key):
            return f"{x.get(key)}@{x['location']}" if x.get("location") else str(x.get(key))
        plan["vlans"][:] = [v for v in plan["vlans"] if ref(v, "id") != rest[1]]
        plan["subnets"][:] = [s for s in plan["subnets"] if ref(s, "vlan") != rest[1]]
    elif rest == ["addresses"]:
        ip = str(body.get("ip", ""))
        if any(a["ip"] == ip for s in plan["subnets"] for a in s["addresses"]):
            raise ValidationError(f"{ip} is already claimed")
        prefix = ".".join(ip.split(".")[:3]) + "."
        sub = next((s for s in plan["subnets"] if s["cidr"].startswith(prefix)), None)
        if sub is None:
            raise ValidationError(f"{ip} is in none of {site}'s subnets")
        sub["addresses"].append({"ip": ip, "kind": body.get("kind", "static"), "name": body.get("name", ""),
                                 "mac": body.get("mac", ""), "owner": body.get("owner", ""),
                                 "notes": body.get("notes", ""), "dns": body.get("dns") == "on", "options": []})
        sub["addresses"].sort(key=lambda a: tuple(int(p) for p in a["ip"].split(".")))
    elif len(rest) == 3 and rest[0] == "addresses" and rest[2] == "delete":
        for s in plan["subnets"]:
            s["addresses"][:] = [a for a in s["addresses"] if a["ip"] != rest[1]]
    return {**NOTHING, "result": {}, "site": site, "own": site == HERE}


def fake_ipam(state, who, method, route, body):
    """Purpose: The fake agent's address manager (manual 1.10.4.35, 1.10.4.40): its reads over the sample plan
             (fabriclib's own view of it), its plan changes in memory, the options page's changes, a scan, a request
             and Sync now answered with samples; nothing is written or applied.
    Inputs:  state — DevState; who — {"user", "perms"}; method — "GET" or "POST"; route — segments after
             /v1/; body — dict.
    Returns: the answer, or None for another route (or without fabriclib, which the views need).
    Fails:   ValidationError as the agent refuses.
    Feeds:   fake_agent (GET and POST), fake_pending (a held change at Apply)."""
    if networks_view is None or route[:1] not in (["networks"], ["ipam"]):
        return None
    if method == "GET":
        return _read(state, route)
    if route[0] == "networks" and len(route) >= 3:
        return _change(state, route, body)
    if route == ["ipam", "scan", "record"]:
        return {"address": {"ip": body.get("ip"), "kind": body.get("kind")}, **_change(state, route, body)}
    if route == ["ipam", "scan"]:
        return {**SAMPLE_SCAN, "subnet": {**SAMPLE_SCAN["subnet"], "cidr": body.get("subnet") or "10.1.20.0/24"}}
    if route == ["ipam", "scan", "request"]:
        site = _site(state, str(body.get("site", "")))
        return {"id": "scan-dev", "site": site, "subnet": body.get("subnet"), "cidr": body.get("subnet"),
                "state": "pending", "requested_by": HERE, "actor": who["user"]}
    if route == ["ipam", "sync"]:
        return {"state": "done", "kea_restarted": True, "firewall": False, "dns_pending": False,
                "dns": {"zones": ["home.arpa"]}}
    if len(route) == 2 and route[1] in ("options", "classes", "option-defs", "netboot"):
        _site(state, str(body.get("site", "")))
        return {"what": route[1], **NOTHING, "result": {}, "site": body.get("site") or HERE}
    return None
