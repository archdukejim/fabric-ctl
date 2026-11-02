from fabriclib.dns.common.zone_records import zone_records

TYPES = {"PTR", "DHCID"}          # what Kea writes in a reverse zone (2.1.10.7)
KEPT_HEAD = "\n\n; kept from DHCP's registrations (Kea's key; 2.1.10.7)\n"   # where the kept records begin


def merge_dynamic_records(zone, new_text, old_text):
    """Purpose: keep the PTR and DHCID records Kea wrote in a reverse zone when fabric installs its regenerated file
             (2.1.10.7, manual 1.10.3.4): the old file holds them once BIND has been frozen (it writes its copy).
    Inputs:  zone — the reverse zone's name; new_text — fabric's regenerated file; old_text — the file being replaced
             (as BIND wrote it), or "" when there is none.
    Returns: new_text with the old file's PTR and DHCID records appended (absolute owners) for every owner the new
             file has no PTR for; new_text unchanged when there are none. Fabric's own PTRs win.
    Fails:   never.
    Feeds:   dns/install_zone_file (reverse zones)."""
    static = {o for o, t, _ in zone_records(new_text, zone, TYPES) if t == "PTR"}
    keep = [r for r in zone_records(old_text or "", zone, TYPES) if r[0] not in static]
    if not keep:
        return new_text
    lines = [f"{o:<40} {t:<6} {d}" for o, t, d in keep]
    return new_text.rstrip("\n") + KEPT_HEAD + "\n".join(lines) + "\n"
