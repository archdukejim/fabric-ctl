from fabriclib.common.errors import ValidationError


def show_netboot(overview, target):
    """Purpose: `fabricctl ipam netboot show` as text (manual 1.10.4.25): the preset of a VLAN's subnets, a subnet or a
             reservation, or "off", and the classes Kea gets for it.
    Inputs:  overview — options_overview's result; target — a VLAN ID, a subnet's name or network, or an address.
    Returns: str (ends with a newline).
    Fails:   ValidationError when nothing in the site's plan matches the target.
    Feeds:   run_option_command (netboot show)."""
    text = str(target or "").strip()
    found = []
    for s in overview.get("subnets") or []:
        if text in (s["name"], s["cidr"]) or (text.isdigit() and s.get("vlan") == int(text)):
            found.append((f"subnet {s['name']} ({s['cidr']})", s.get("netboot"), f"fabric-nb-s{s.get('id')}-*"))
        for r in s["reservations"]:
            if text == r["ip"]:
                found.append((f"reservation {r['ip']} {r['name']}", r.get("netboot"), f"fabric-nb-a-{r['ip']}-*"))
    if not found:
        raise ValidationError(f"{text!r} is no VLAN, subnet or reservation of {overview['site']}'s plan")
    lines = []
    for label, preset, classes in found:
        if not preset:
            lines.append(f"{label}: netboot off")
            continue
        lines.append(f"{label}: netboot on, boot server {preset['server']} (Kea classes {classes})")
        for key, what in (("bios", "PXE BIOS file"), ("uefi", "PXE UEFI x64 file"), ("arm64", "PXE UEFI arm64 file"),
                          ("ipxe", "iPXE script"), ("http", "UEFI HTTP boot URL")):
            if preset.get(key):
                lines.append(f"  {what}: {preset[key]}")
    return "\n".join(lines) + "\n"
