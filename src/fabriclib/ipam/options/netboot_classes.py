import ipaddress

IPXE = "substring(option[77].hex,0,4) == 'iPXE'"
HTTP = "substring(option[60].hex,0,10) == 'HTTPClient'"
ARCH = {"bios": "option[93].hex == 0x0000", "uefi": "(option[93].hex == 0x0007 or option[93].hex == 0x0009)",
        "arm64": "option[93].hex == 0x000b"}


def _kinds(preset):
    """Purpose: the classes one preset needs, each with its test (without the scope) and what it hands out: iPXE
             first, then HTTP boot, then PXE by architecture, each later one excluding the earlier, so a client
             matches one (manual 1.10.4.25).
    Inputs:  preset — check_netboot's preset.
    Returns: list of (kind, test, boot file or URL, options list, PXE: bool).
    Fails:   never.
    Feeds:   netboot_classes."""
    out = []
    if preset.get("ipxe"):
        out.append(("ipxe", IPXE, preset["ipxe"], [{"name": "boot-file-name", "data": preset["ipxe"]}], False))
    if preset.get("http"):
        test = f"{HTTP} and not ({IPXE})"
        out.append(("http", test, preset["http"], [{"name": "boot-file-name", "data": preset["http"]},
                                                   {"name": "vendor-class-identifier", "data": "HTTPClient"}], False))
    for kind in ("bios", "uefi", "arm64"):
        if preset.get(kind):
            test = f"{ARCH[kind]} and not ({IPXE}) and not ({HTTP})"
            out.append((kind, test, preset[kind], [{"name": "boot-file-name", "data": preset[kind]},
                                                   {"name": "tftp-server-name", "data": preset["server"]}], True))
    return out


def _classes(prefix, scope, preset, additional):
    """Purpose: one preset's Kea classes in fabric's class form.
    Inputs:  prefix — the classes' common name; scope — a test every class starts with ("" for none); preset —
             check_netboot's; additional — bool: evaluated only when a subnet names them (Kea's
             only-in-additional-list).
    Returns: list of class dicts {name, test, options, boot_file_name, next_server?, server_hostname?, additional?}.
    Fails:   never.
    Feeds:   netboot_classes."""
    try:
        next_server = str(ipaddress.IPv4Address(preset["server"]))
    except ValueError:
        next_server = ""
    out = []
    for kind, test, boot, options, pxe in _kinds(preset):
        c = {"name": f"{prefix}-{kind}", "test": f"{scope} and {test}" if scope else test, "options": options,
             "boot_file_name": boot}
        if pxe and next_server:
            c["next_server"] = next_server
        if pxe and not next_server:
            c["server_hostname"] = preset["server"]
        if additional:
            c["additional"] = True
        out.append(c)
    return out


def netboot_classes(plan):
    """Purpose: the Kea client classes a site's netboot presets need (decision 2.1.10.25, manual 1.10.4.25): for a
             subnet with a preset, classes `fabric-nb-s<id>-<kind>` evaluated only for it (only-in-additional-list,
             named in its evaluate-additional-classes); for a reservation with one, a marker class
             `fabric-nb-a-<address>` the reservation carries and classes `fabric-nb-a-<address>-<kind>` testing it
             after the host lookup (member('KNOWN') defers them there).
    Inputs:  plan — a site's plan (subnets with "id", "netboot" and their addresses' "netboot").
    Returns: {"classes": [class dicts, markers first], "subnets": {subnet name: [class names]}, "reservations":
             {address: [the marker]}}.
    Fails:   never.
    Feeds:   plan_to_dhcp, effective_options."""
    classes, subnets, reservations = [], {}, {}
    for s in plan.get("subnets") or []:
        if s.get("netboot") and s.get("id"):
            made = _classes(f"fabric-nb-s{s['id']}", "", s["netboot"], True)
            classes += made
            subnets[s["name"]] = [c["name"] for c in made]
        for a in s.get("addresses") or []:
            if a.get("netboot") and a.get("kind") == "reservation":
                marker = f"fabric-nb-a-{a['ip']}"
                classes.insert(0, {"name": marker, "marker": True})
                classes += _classes(marker, f"member('KNOWN') and member('{marker}')", a["netboot"], False)
                reservations[a["ip"]] = [marker]
    return {"classes": classes, "subnets": subnets, "reservations": reservations}
