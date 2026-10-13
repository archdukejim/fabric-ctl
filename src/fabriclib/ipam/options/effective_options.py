from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.fields import find_address, find_subnet
from fabriclib.ipam.options.catalogue import option_label
from fabriclib.ipam.options.merge_option_sets import merge_option_sets
from fabriclib.ipam.options.netboot_classes import netboot_classes

EMPTY = {"options": [], "option_defs": [], "client_classes": []}


def _fabric_globals(v):
    """Purpose: the global options fabric itself sets because it runs the service (manual 1.10.4.6.2), as the Kea
             template sets them: DNS, NTP, the domain and its search list.
    Inputs:  v — fabric's rendered vars (host_ip, domain, dhcp, ntp_serve), or None.
    Returns: list of {name, data}; with no vars, the data says whose they are.
    Fails:   never.
    Feeds:   effective_options."""
    if not v:
        return [{"name": n, "data": "(fabric's)"} for n in
                ("domain-name-servers", "ntp-servers", "domain-name", "domain-search")]
    d = v.get("dhcp") or {}
    host, domain = v.get("host_ip", ""), v.get("domain", "")
    out = [{"name": "domain-name-servers", "data": ", ".join(d.get("dns") or [host])}]
    ntp = d.get("ntp") if "ntp" in d else ([host] if v.get("ntp_serve", True) else [])
    if ntp:
        out.append({"name": "ntp-servers", "data": ", ".join(ntp)})
    out.append({"name": "domain-name", "data": d.get("domain") or domain})
    zone = f"{d.get('ddns_subdomain') or 'dhcp'}.{domain}"
    out.append({"name": "domain-search", "data": ", ".join(([zone] if d.get("ddns", True) else []) + [domain])})
    return out


def _layer(rows, options, source, defs):
    """Purpose: one level's options laid over the ones below it: an option of the same identity replaces the lower
             one, which is recorded as overridden.
    Inputs:  rows — {key: row}, changed in place; options — the level's list; source — its label; defs — the
             definitions in force.
    Returns: None.
    Fails:   never.
    Feeds:   effective_options."""
    for o in options or []:
        label = option_label(o, defs)
        below = rows.get(label["key"])
        row = {"code": label["code"], "name": label["name"], "space": label["space"], "data": o.get("data", ""),
               "source": source, "provided": label["provided"],
               "overrides": (below["overrides"] + [below["source"]]) if below else []}
        row["fabric_overridden"] = row["provided"] and source != "fabric"
        rows[label["key"]] = row


def effective_options(plan, kind, target="", v=None, settings=None):
    """Purpose: the provenance of DHCP options (decision 2.1.10.14, manual 1.10.4.24.3): for the site, a subnet or a
             reservation's address, every option a client there ends up with, where each comes from and what it
             overrides, in Kea's order (fabric's global options, the organisation's, the site's, the settings' not yet
             moved; then for a subnet fabric's router and the subnet's; for an address also the reservation's); then
             each client class that may apply there (the organisation's and site's classes, and the netboot preset's
             classes for that subnet or address) with its options as conditional rows, each marked when the subnet or
             address overrides it (Kea ranks a class below the subnet). One function: the Networks tab, the options
             page and `fabricctl ipam option show` use it.
    Inputs:  plan — the site's plan (site_plan: org_options, site_options, subnets with options, netboot, addresses);
             kind — "site", "subnet" or "address"; target — the subnet's name or network, or the address ("" for the
             site); v — fabric's rendered vars for fabric's own values (None: shown as fabric's); settings — the
             options the settings still carry ({"options", "option_defs", "client_classes"}) or None.
    Returns: {"target": label, "rows": [{"code", "name", "space", "data", "source", "provided" (fabric provides it),
             "fabric_overridden" (an admin's option replaced fabric's), "overrides" (sources below it, lowest
             first)}] sorted by code, "classes": [{"name", "owner" ("organisation", "site", "netboot"), "test",
             "fields" (next_server, server_hostname, boot_file_name when set), "rows": [... as above, plus
             "overridden_by": the subnet or address that replaces it, or ""]}]}.
    Fails:   ValidationError: an unknown kind; no such subnet or address.
    Feeds:   show_options, options_overview, agent route GET /v1/ipam/options/<site>/<target>, the Networks tab."""
    if kind not in ("site", "subnet", "address"):
        raise ValidationError("effective options: of the site, a subnet or an address")
    org, mine = plan.get("org_options") or EMPTY, plan.get("site_options") or EMPTY
    merged = merge_option_sets(org, mine, settings)
    defs = merged["option_defs"]
    rows = {}
    _layer(rows, _fabric_globals(v), "fabric", defs)
    _layer(rows, org.get("options"), "organisation", defs)
    _layer(rows, mine.get("options"), f"site {plan['site']}", defs)
    _layer(rows, (settings or EMPTY).get("options"), "settings (vars.yaml, not moved yet)", defs)
    label, top, boot = f"site {plan['site']}", {}, netboot_classes(plan)
    names = []
    if kind in ("subnet", "address"):
        if kind == "subnet":
            sub, addr = find_subnet(plan, target), None
        else:
            addr, sub = find_address(plan, target)
        if sub.get("gateway"):
            _layer(rows, [{"name": "routers", "data": sub["gateway"]}], "fabric (the subnet's gateway)", defs)
        _layer(rows, sub.get("options"), f"subnet {sub['name']}", defs)
        _layer(top, sub.get("options"), f"subnet {sub['name']}", defs)
        names += boot["subnets"].get(sub["name"]) or []
        label = f"subnet {sub['name']}"
        if addr is not None:
            _layer(rows, addr.get("options"), f"address {addr['ip']}", defs)
            _layer(top, addr.get("options"), f"address {addr['ip']}", defs)
            marker = (boot["reservations"].get(addr["ip"]) or [None])[0]
            names += [c["name"] for c in boot["classes"] if marker and c["name"].startswith(marker + "-")]
            label = f"address {addr['ip']}"
    owners = {c["name"]: "organisation" for c in org.get("client_classes") or []}
    owners.update({c["name"]: "site" for c in mine.get("client_classes") or []})
    classes = []
    for c in merged["client_classes"] + [c for c in boot["classes"] if c["name"] in names]:
        crow = {}
        _layer(crow, c.get("options"), f"class {c['name']}", defs)
        for key, row in crow.items():
            below = rows.get(key)
            row["overrides"] = [s for s in ([below["source"]] if below else []) if not s.startswith(("subnet",
                                                                                                   "address"))]
            row["overridden_by"] = top[key]["source"] if key in top else ""
        classes.append({"name": c["name"], "owner": owners.get(c["name"], "netboot"), "test": c.get("test", ""),
                        "fields": {k: c[k] for k in ("next_server", "server_hostname", "boot_file_name") if c.get(k)},
                        "rows": sorted(crow.values(), key=lambda r: (r["code"] is None, r["code"] or 0, r["name"]))})
    return {"target": label, "rows": sorted(rows.values(), key=lambda r: (r["code"] is None, r["code"] or 0,
                                                                         r["name"])),
            "classes": classes}
