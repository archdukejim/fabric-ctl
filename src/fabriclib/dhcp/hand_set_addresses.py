import ipaddress

from fabriclib.dns.reverse_zones import REVERSE_SUFFIXES


def hand_set_addresses(v):
    """Purpose: every address a record set by hand names: the A and AAAA records of fabric's forward zones (the
             settings' `dns:`, and the plan's addresses with DNS on once load_address_plan has added them), whose
             names outrank DHCP's (2.1.10.20, 2.1.10.22).
    Inputs:  v — the apply's checked settings (dns).
    Returns: sorted list of addresses as text, each in its canonical form (an unreadable one is left out).
    Fails:   never.
    Feeds:   deploy/restart_changed (the apply's cleanup), dhcp/keep_hand_set_addresses (for the hourly timer)."""
    found = set()
    for key, recs in (v.get("dns") or {}).items():
        if key.endswith(REVERSE_SUFFIXES) or not isinstance(recs, dict):
            continue
        for rtype in ("A", "AAAA"):
            for rec in recs.get(rtype) or []:
                try:
                    found.add(str(ipaddress.ip_address(str(rec.get("ip") or "").strip())))
                except ValueError:
                    continue
    return sorted(found)
