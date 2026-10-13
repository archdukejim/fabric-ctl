from fabriclib.ipam.options.option_label import option_label


def _option(o, defs):
    """Purpose: one option as a line: its code and standard name, its value, its flags.
    Inputs:  o — an option; defs — the definitions in force.
    Returns: str.
    Fails:   never.
    Feeds:   show_options."""
    label = option_label(o, defs)
    flags = [f for f, on in (("always sent", o.get("always_send")), ("csv off", o.get("csv_format") is False)) if on]
    space = "" if label["space"] == "dhcp4" else f" [{label['space']}]"
    return (f"{str(label['code'] or '-'):>4}  {label['name'] or '(no name)':<28}{space} {o.get('data', '')}"
            + (f"  ({', '.join(flags)})" if flags else ""))


def _set(lines, title, one, defs):
    """Purpose: one option set's lines: its options, definitions and classes.
    Inputs:  lines — list, appended to; title — str; one — the set or None; defs — the definitions in force.
    Returns: None.
    Fails:   never.
    Feeds:   show_options."""
    lines.append(title)
    if one is None:
        lines.append("  (not in the domain yet: apply at the top site)")
        return
    for o in one.get("options") or []:
        lines.append("  " + _option(o, defs))
    for d in one.get("option_defs") or []:
        lines.append(f"  defines {d['name']} = code {d['code']} ({d['type']}{', array' if d.get('array') else ''})")
    for c in one.get("client_classes") or []:
        lines.append(f"  class {c['name']}: {c['test']}")
        for key in ("next_server", "server_hostname", "boot_file_name"):
            if c.get(key):
                lines.append(f"      {key.replace('_', ' ')}: {c[key]}")
        for o in c.get("options") or []:
            lines.append("      " + _option(o, defs))
    if not any(one.get(k) for k in ("options", "option_defs", "client_classes")):
        lines.append("  (none)")


def _preset(p):
    """Purpose: a netboot preset in one line.
    Inputs:  p — the preset.
    Returns: str.
    Fails:   never.
    Feeds:   show_options."""
    return "netboot: " + ", ".join(f"{k} {p[k]}" for k in ("server", "bios", "uefi", "arm64", "ipxe", "http") if k in p)


def show_options(overview):
    """Purpose: `fabricctl ipam option show` as text (manual 1.10.4.24.5): with a target, the effective options with
             their sources, the "provided by fabric" markers and the classes that may apply; without one, the
             organisation's and the site's sets, what the settings still carry, each subnet's and reservation's own
             options and presets, and whether this site may edit the organisation's options.
    Inputs:  overview — options_overview's result.
    Returns: str (ends with a newline).
    Fails:   never.
    Feeds:   run_option_command (option show, netboot show)."""
    org, mine = overview.get("org") or {}, overview.get("site_options") or {}
    defs = list(org.get("option_defs") or []) + list(mine.get("option_defs") or [])
    eff = overview.get("effective")
    lines = []
    if eff:
        lines.append(f"{eff['target']}: the options a client gets, and where each comes from")
        for r in eff["rows"]:
            mark = (" [provided by fabric, overridden]" if r["fabric_overridden"] else
                    " [provided by fabric]" if r["provided"] else "")
            over = f" (overrides {', '.join(r['overrides'])})" if r["overrides"] else ""
            lines.append(f"{str(r['code'] or '-'):>4}  {r['name'] or '(no name)':<28} {r['data']}  <- {r['source']}"
                         f"{mark}{over}")
        for c in eff["classes"]:
            lines.append(f"  clients in class {c['name']} ({c['owner']}): {c['test']}")
            for key, value in c["fields"].items():
                lines.append(f"      {key.replace('_', ' ')}: {value}")
            for r in c["rows"]:
                note = f"  (replaced by {r['overridden_by']})" if r["overridden_by"] else ""
                lines.append(f"    {str(r['code'] or '-'):>4}  {r['name'] or '(no name)':<28} {r['data']}{note}")
        return "\n".join(lines) + "\n"
    _set(lines, "the organisation" + ("" if overview.get("org_editable") else " (this site may not edit it)"),
         overview.get("org"), defs)
    _set(lines, f"site {overview['site']}", mine, defs)
    if overview.get("settings"):
        _set(lines, "still in this site's settings (moved into the plan at the next apply)", overview["settings"],
             defs)
    for s in overview.get("subnets") or []:
        head = f"subnet {s['name']} ({s['cidr']})"
        own = [_option(o, defs) for o in s["options"]] + ([_preset(s["netboot"])] if s.get("netboot") else [])
        if own:
            lines.append(head)
            lines += ["  " + x for x in own]
        for r in s["reservations"]:
            own = [_option(o, defs) for o in r["options"]] + ([_preset(r["netboot"])] if r.get("netboot") else [])
            if own:
                lines.append(f"  reservation {r['ip']} {r['name']}")
                lines += ["    " + x for x in own]
    if overview.get("root"):
        lines.append("sites that may edit the organisation's options: the top site"
                     + "".join(f", {e}" for e in overview.get("org_editors") or []))
    return "\n".join(lines) + "\n"
