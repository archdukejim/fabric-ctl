import ipaddress

from fabriclib.dns.ptr_for_ip import ptr_for_ip


def dhcp_reverse_zones(v):
    """Purpose: the reverse zones Kea registers PTR records in (2.1.10.7, manual 1.10.3.4): every zone that holds an
             address of a DHCP pool or of a reservation DHCP registers (not one whose names are set by hand,
             `"ddns": False`, 2.1.10.20), private ranges only (as ptr_for_ip decides).
    Inputs:  v — rendered vars: install_kea; dhcp {ddns (default true), subnets [{pools ["lo - hi"], reservations
             [{ip, ddns}]}]} as normalize_dhcp returns them.
    Returns: sorted list of zone names (e.g. "0.20.10.in-addr.arpa"); [] with DHCP or its DNS registration off.
    Fails:   never (pools and addresses were checked by normalize_dhcp).
    Feeds:   deploy/check_settings (dhcp_reverse_zones: dns/reverse_zones, BIND's zone grants, Kea's reverse DDNS)."""
    d = v.get("dhcp") or {}
    if not v.get("install_kea") or not d.get("ddns", True):
        return []
    zones = set()
    for s in d.get("subnets") or []:
        for pool in s.get("pools") or []:
            lo, hi = (ipaddress.ip_address(x.strip()) for x in str(pool).split("-"))
            block = ipaddress.ip_network(f"{lo}/24", strict=False)
            while block.network_address <= hi:            # one /24 zone at a time across the pool
                zone, _ = ptr_for_ip(block.network_address + 1)
                if zone:
                    zones.add(zone)
                block = ipaddress.ip_network(f"{block.broadcast_address + 1}/24", strict=False)
        for r in s.get("reservations") or []:
            if r.get("ddns") is False:                     # its names are set by hand, never Kea's (2.1.10.20)
                continue
            zone, _ = ptr_for_ip(r.get("ip"))
            if zone:
                zones.add(zone)
    return sorted(zones)
