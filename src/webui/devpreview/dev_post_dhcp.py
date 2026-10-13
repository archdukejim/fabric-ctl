import urllib.parse

from webui.devpreview.sample_data import SAMPLE_DHCP


def _where(form):
    """Purpose: where a dev-preview option goes: the sample's global list, or the first subnet / named class.
    Inputs:  form — dict with scope and target.
    Returns: the list of options to change.
    Fails:   never (falls back to the global list).
    Feeds:   dev_post_dhcp."""
    if form.get("scope") == "subnet" and SAMPLE_DHCP["subnets"]:
        return SAMPLE_DHCP["subnets"][0].setdefault("options", [])
    if form.get("scope") == "class":
        for c in SAMPLE_DHCP["client_classes"]:
            if c["name"] == form.get("target"):
                return c.setdefault("options", [])
    return SAMPLE_DHCP["options"]


def dev_post_dhcp(h, path, form):
    """Purpose: the Kea tab's changes acted out on the sample data in memory (nothing applied): reservations,
             subnets, options, client classes.
    Inputs:  h — the dev handler (send); path — /kea/…; form — dict.
    Returns: True when the path was handled (303 back to /kea with a message); None otherwise.
    Fails:   never for form values (the dev preview does not validate; fabriclib does in production).
    Feeds:   dev_post_action."""
    if not path.startswith("/kea/"):
        return None
    if path.startswith("/kea/options/"):     # the DHCP options page: shown, never saved (1.10.4.24.6)
        h.send(303, b"", location="/kea/options?" + urllib.parse.urlencode(
            {"msg": "Saved (dev preview: nothing saved or applied)."}))
        return True
    parts = [urllib.parse.unquote(p) for p in path.split("/")[2:]]
    subnets = SAMPLE_DHCP["subnets"]
    if parts in (["on"], ["off"]):
        msg = "DHCP is on" if parts == ["on"] else "DHCP is off: Kea stopped; its settings and leases are kept"
    elif parts == ["reservations"]:
        subnets[0]["reservations"].append({"mac": form.get("mac", "").lower(), "ip": form.get("ip", ""),
                                           "hostname": form.get("hostname", "")})
        msg = f"Reserved {form.get('ip', '')}"
    elif parts[:1] == ["reservations"]:
        subnets[0]["reservations"][:] = [r for r in subnets[0]["reservations"] if r["mac"] != parts[1]]
        msg = "Reservation removed"
    elif parts == ["subnets"]:
        subnets.append({"subnet": form.get("network", ""), "name": form.get("name", ""),
                        "vlan": int(form["vlan"]) if form.get("vlan", "").isdigit() else None,
                        "routers": form.get("router", ""), "notes": form.get("notes", ""),
                        "pools": [p.strip() for p in form.get("pools", "").splitlines() if p.strip()],
                        "reservations": []})
        msg = f"Subnet {form.get('network', '')} added"
    elif parts == ["subnets", "delete"]:
        subnets[:] = [s for s in subnets if s["subnet"] != form.get("subnet")] or subnets
        msg = f"Subnet {form.get('subnet', '')} removed"
    elif parts == ["options"]:
        _where(form).append({"name": form.get("option", ""), "data": form.get("data", "")})
        msg = f"Option {form.get('option', '')} set"
    elif parts == ["options", "delete"]:
        opts = _where(form)
        opts[:] = [o for o in opts if str(o.get("name", o.get("code"))) != form.get("option")]
        msg = f"Option {form.get('option', '')} removed"
    elif parts == ["classes"]:
        SAMPLE_DHCP["client_classes"].append({"name": form.get("name", ""), "test": form.get("test", ""),
                                              "next_server": form.get("next_server", ""),
                                              "boot_file_name": form.get("boot_file", ""), "options": []})
        msg = f"Client class {form.get('name', '')} added"
    elif parts[:1] == ["classes"]:
        SAMPLE_DHCP["client_classes"][:] = [c for c in SAMPLE_DHCP["client_classes"] if c["name"] != parts[1]]
        msg = f"Client class {parts[1]} removed"
    else:
        msg = "Saved"
    h.send(303, b"", location="/kea?" + urllib.parse.urlencode({"msg": msg + " (dev preview: nothing applied)."}))
    return True
