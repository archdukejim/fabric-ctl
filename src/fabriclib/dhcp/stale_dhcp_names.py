import ipaddress

from fabriclib.dns.common.zone_records import zone_records


def _canonical(text):
    """Purpose: an address in its canonical form, to compare AAAA records written in any form.
    Inputs:  text — str.
    Returns: str, or the text itself when it is not an address.
    Fails:   never.
    Feeds:   stale_dhcp_names."""
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return text.strip()


def stale_dhcp_names(text, zone, addresses):
    """Purpose: the records of DHCP's zone left behind for addresses whose names are now set by hand (2.1.10.22):
             each A or AAAA record whose address one of them is, and a name's DHCID once none of its addresses is
             left. A name pointing anywhere else is not listed.
    Inputs:  text — dhcp.<domain>'s zone file as BIND writes it; zone — its name; addresses — hand_set_addresses().
    Returns: list of (owner FQDN with trailing dot, type, rdata), the address records first for each name.
    Fails:   never.
    Feeds:   dhcp/clear_stale_dhcp_names."""
    covered = {_canonical(a) for a in addresses}
    names = {}
    for owner, rtype, rdata in zone_records(text, zone, {"A", "AAAA", "DHCID"}):
        names.setdefault(owner, []).append((rtype, rdata))
    stale = []
    for owner, recs in names.items():
        held = [(t, d) for t, d in recs if t in ("A", "AAAA")]
        gone = [(t, d) for t, d in held if _canonical(d) in covered]
        if not gone:
            continue
        stale += [(owner, t, d) for t, d in gone]
        if len(gone) == len(held):
            stale += [(owner, t, d) for t, d in recs if t == "DHCID"]
    return stale
