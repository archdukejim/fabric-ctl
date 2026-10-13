import urllib.parse

from webui.devpreview.fabric_rules import suggest_split, suggest_subnet
from webui.devpreview.sample_networks import SAMPLE_NETWORK_READ


def _act(plan, site, rest, form):
    """Purpose: one Networks tab change on the sample plan, in memory, with the few refusals the preview shows.
    Inputs:  plan — the site's sample plan; site — str; rest — segments after the site; form — dict.
    Returns: (message, error): one of them "".
    Fails:   never.
    Feeds:   dev_post_networks."""
    if rest == ["block"]:
        number = form.get("number", "")
        if not number.isdigit() or not 1 <= int(number) <= 255:
            return "", f"site number {number!r}: a whole number from 1 to 255"
        for s in SAMPLE_NETWORK_READ["sites"]:
            if s["name"] == site:
                s["block"] = int(number)
        return f"Site number set to {number}.", ""
    if rest == ["vlans"]:
        vid = form.get("id", "")
        if not vid.isdigit() or not 1 <= int(vid) <= 4094:
            return "", f"VLAN ID {vid!r} is a number from 1 to 4094"
        if any(v["id"] == int(vid) for v in plan["vlans"]):
            return "", f"VLAN {vid} is already in this site's plan"
        name = form.get("name", "").strip().lower() or f"vlan{vid}"
        plan["vlans"].append({"id": int(vid), "name": name, "purpose": form.get("purpose", ""),
                              "access": form.get("access", "full"), "notes": form.get("notes", "")})
        block = next((s["block"] for s in SAMPLE_NETWORK_READ["sites"] if s["name"] == site), None)
        cidr = form.get("subnet") or (suggest_subnet(block, int(vid)) if suggest_subnet else None)
        if form.get("no_subnet") != "on" and cidr:
            split = suggest_split(cidr) if suggest_split else {"gateway": "", "ranges": []}
            plan["subnets"].append({"name": name, "cidr": cidr, "vlan": int(vid), "kind": "dhcp",
                                    "gateway": form.get("gateway") or split["gateway"], "dhcp": True, "id": None,
                                    "relay": "", "notes": "", "allow_overlap": "", "options": [],
                                    "ranges": split["ranges"] if form.get("split", "on") == "on" else [],
                                    "addresses": []})
        plan["vlans"].sort(key=lambda v: v["id"])
        return f"VLAN {vid} ({name}) added.", ""
    if len(rest) == 3 and rest[0] == "vlans" and rest[2] == "delete":
        plan["vlans"][:] = [v for v in plan["vlans"] if str(v["id"]) != rest[1]]
        plan["subnets"][:] = [s for s in plan["subnets"] if str(s.get("vlan")) != rest[1]]
        return "VLAN removed.", ""
    if len(rest) == 2 and rest[0] == "addresses":
        for s in plan["subnets"]:
            for a in s["addresses"]:
                if a["ip"] == rest[1]:
                    if form.get("role", a.get("role")) and form.get("kind", a["kind"]) != "reservation":
                        return "", f"{rest[1]}: only a reservation names a device role"
                    a.update({k: form[k] for k in ("kind", "name", "mac", "owner", "notes", "role") if k in form})
                    if "dns" in form:
                        a["dns"] = form["dns"] == "on"
                    return "Address saved.", ""
        return "", f"no address {rest[1]} in {site}'s plan"
    if rest == ["addresses"]:
        ip = form.get("ip", "")
        if form.get("role") and form.get("kind", "static") != "reservation":
            return "", f"{ip}: only a reservation names a device role"
        for s in plan["subnets"]:
            if any(a["ip"] == ip for a in s["addresses"]):
                return "", f"{ip} is already claimed"
        sub = next((s for s in plan["subnets"] if str(s.get("vlan")) == form.get("vlan")), None)
        if sub is None:
            return "", f"{ip} is in none of {site}'s subnets"
        sub["addresses"].append({"ip": ip, "kind": form.get("kind", "static"), "name": form.get("name", ""),
                                 "mac": form.get("mac", ""), "owner": form.get("owner", ""),
                                 "notes": form.get("notes", ""), "dns": form.get("dns") == "on", "options": [],
                                 "role": form.get("role", "")})
        sub["addresses"].sort(key=lambda a: tuple(int(p) for p in a["ip"].split(".")))
        return f"{ip} recorded.", ""
    if len(rest) == 3 and rest[0] == "addresses" and rest[2] == "delete":
        for s in plan["subnets"]:
            s["addresses"][:] = [a for a in s["addresses"] if a["ip"] != rest[1]]
        return "Address removed.", ""
    return "Saved.", ""


def dev_post_networks(h, path, form):
    """Purpose: the Networks tab's changes acted out on the sample plan in memory (nothing written or applied): the
             site's number, a VLAN added or removed, an address recorded, changed or removed (a device role only on
             a reservation); the other forms say saved.
    Inputs:  h — the dev handler (send); path — /networks/<site>/…; form — dict.
    Returns: True when the path was handled (303 back to the tab with msg or err); None otherwise.
    Fails:   never for form values.
    Feeds:   dev_post_action."""
    if not path.startswith("/networks/"):
        return None
    parts = [urllib.parse.unquote(p) for p in path.split("/")[2:]]
    site, rest = parts[0], parts[1:]
    back = {"site": site, **({"subnet": form["back"]} if form.get("back") else {})}
    plan = SAMPLE_NETWORK_READ["plans"].get(site)
    if plan is None:
        back["err"] = f"site {site!r} is not this site or one below it"
    else:
        msg, err = _act(plan, site, rest, form)
        back.update({"err": err} if err else {"msg": msg + " (dev preview: nothing written or applied)."})
    h.send(303, b"", location="/networks?" + urllib.parse.urlencode(back))
    return True
