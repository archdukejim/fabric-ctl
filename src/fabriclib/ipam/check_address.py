import ipaddress

from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.normalize_dhcp import LABEL_RE, MAC_RE
from fabriclib.dhcp.normalize_options import normalize_options
from fabriclib.ipam.common.fields import ADDRESS_KINDS, host_in, ipv4, notes, one_line


def check_address(addr, subnet, plan, current=None):
    """Purpose: one address of a subnet checked against the model's rules (manual 1.10.4.3.2): one address, one claim
             (a static address, a reservation or the gateway; a second is refused naming the first); inside a dhcp
             range only a reservation; a static address outside every static range is warned about, never refused; a
             reservation has a MAC, unique among the site's reservations; a name is one DNS label, and one published
             in DNS (an A and a PTR in the site's zone, 1.10.4.5; a reservation's too, beside the name DHCP registers
             in dhcp.<domain>, 2.1.10.17) is unique among the site's.
    Inputs:  addr — {"ip", "kind", "name", "mac", "owner", "notes", "dns", "options"}; subnet — the subnet's plan entry
             (cidr, gateway, dhcp, ranges, addresses); plan — the site's plan (every subnet's addresses, for MACs and
             DNS names); current — the address being changed (its own claim is not a second one), None for a new one.
    Returns: (the address normalized {"ip", "kind", "name", "mac" (lower-case, colons), "owner", "notes", "dns",
             "options"}, warnings: list of str).
    Fails:   ValidationError: not a host of the subnet, an unknown kind, a second claim (named), a non-reservation in a
             dhcp range, a reservation without a MAC or with a MAC another reservation has, a bad MAC or name, DNS
             without a name, a DNS name another address publishes, an owner over one line, notes over 500
             characters, bad options.
    Feeds:   add_address, set_address."""
    net = ipaddress.ip_network(subnet["cidr"])
    ip = ipv4(addr.get("ip"), "address")
    host_in(ip, net, "address")
    kind = str(addr.get("kind") or "").strip().lower()
    if kind not in ADDRESS_KINDS:
        raise ValidationError(f"address kind {addr.get('kind')!r}: one of {', '.join(ADDRESS_KINDS)}")
    if subnet.get("gateway") == str(ip):
        raise ValidationError(f"{ip} is already claimed: it is the gateway of {subnet['cidr']}")
    for other in subnet.get("addresses") or []:
        if other["ip"] == str(ip) and other["ip"] != current:
            raise ValidationError(f"{ip} is already claimed: a {other['kind']} address"
                                  + (f" ({other['name']})" if other.get("name") else ""))
    mac = str(addr.get("mac") or "").strip().lower().replace("-", ":")
    if mac and not MAC_RE.match(mac):
        raise ValidationError(f"MAC {addr.get('mac')!r}: like aa:bb:cc:dd:ee:ff")
    name = str(addr.get("name") or "").strip().lower()
    if name and not LABEL_RE.match(name):
        raise ValidationError(f"name {addr.get('name')!r} is one DNS label")
    dns = bool(addr.get("dns"))
    others = [a for s in plan.get("subnets") or [] for a in s.get("addresses") or [] if a["ip"] != (current or "")]
    if kind == "reservation":
        if not mac:
            raise ValidationError(f"a reservation needs the device's MAC (--mac) for {ip}")
        taken = next((a for a in others if a["kind"] == "reservation" and a["mac"] == mac), None)
        if taken:
            raise ValidationError(f"MAC {mac} already has a reservation: {taken['ip']}")
    if dns and not name:
        raise ValidationError(f"{ip}: an address published in DNS needs a name (--name)")
    if dns and any(a.get("dns") and a.get("name") == name for a in others):
        raise ValidationError(f"the name {name} is already published in DNS by another address of this site")
    warnings, inside = [], None
    for r in subnet.get("ranges") or []:
        if ipaddress.ip_address(r["first"]) <= ip <= ipaddress.ip_address(r["last"]):
            inside = r
    if inside and inside["kind"] == "dhcp" and kind != "reservation":
        raise ValidationError(f"{ip} lies in the DHCP range {inside['first']} - {inside['last']}: only a reservation "
                              "may be there")
    if kind == "static" and (inside is None or inside["kind"] != "static"):
        warnings.append(f"{ip} is a static address outside the subnet's static ranges")
    if kind == "reservation" and not subnet.get("dhcp"):
        warnings.append(f"{subnet['cidr']} is not served by DHCP: the reservation takes effect once it is")
    options = normalize_options(addr.get("options"), f"address {ip}")
    return ({"ip": str(ip), "kind": kind, "name": name, "mac": mac, "owner": one_line(addr.get("owner"), "owner"),
             "notes": notes(addr.get("notes")), "dns": dns, "options": options}, warnings)
