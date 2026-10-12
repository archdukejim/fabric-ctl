"""The fields of the address plan and the small checks every part of it shares (manual 1.10.4.3)."""
import ipaddress

from fabriclib.common.errors import ValidationError

NOTES_MAX = 500
LINE_MAX = 200
RANGE_KINDS = ("gateway", "static", "dhcp", "reserved")
ADDRESS_KINDS = ("static", "reservation", "infrastructure")
ACCESS = ("full", "guest")


def one_line(text, what, limit=LINE_MAX):
    """Purpose: a short free-text field of the plan (a purpose, an owner, an overlap reason): one line, length-limited.
    Inputs:  text — anything (None is ""); what — the field's name for the message; limit — characters.
    Returns: str, stripped.
    Fails:   ValidationError "<what> is one line of at most <limit> characters".
    Feeds:   the plan's checks (check_vlan, check_subnet, check_address)."""
    out = str(text or "").strip()
    if len(out) > limit or "\n" in out or "\r" in out:
        raise ValidationError(f"{what} is one line of at most {limit} characters")
    return out


def notes(text):
    """Purpose: a notes field of the plan (shown HTML-escaped, never interpreted): length-limited.
    Inputs:  text — anything (None is "").
    Returns: str.
    Fails:   ValidationError "notes are at most 500 characters".
    Feeds:   the plan's checks."""
    out = str(text or "")
    if len(out) > NOTES_MAX:
        raise ValidationError(f"notes are at most {NOTES_MAX} characters")
    return out


def ipv4(text, what):
    """Purpose: an IPv4 address the admin typed.
    Inputs:  text — anything; what — the field's name for the message.
    Returns: ipaddress.IPv4Address.
    Fails:   ValidationError "<what> <text> is not an IPv4 address".
    Feeds:   the plan's checks."""
    try:
        addr = ipaddress.ip_address(str(text).strip())
    except ValueError:
        addr = None
    if addr is None or addr.version != 4:
        raise ValidationError(f"{what} {text!r} is not an IPv4 address")
    return addr


def host_in(addr, net, what):
    """Purpose: refuse an address that is not a usable host of its subnet (outside it, or its network or broadcast
             address where the subnet has them).
    Inputs:  addr — IPv4Address; net — IPv4Network; what — the field's name for the message.
    Returns: None.
    Fails:   ValidationError naming the subnet.
    Feeds:   check_subnet (the gateway), check_range, check_address."""
    if addr not in net:
        raise ValidationError(f"{what} {addr} is outside the subnet {net}")
    if net.prefixlen < 31 and addr in (net.network_address, net.broadcast_address):
        raise ValidationError(f"{what} {addr} is the network's own or broadcast address of {net}")


KEEP = object()          # a field a change leaves as it is (set_vlan, set_address)


def find_vlan(plan, vid):
    """Purpose: a VLAN of the site's plan and its subnet, by ID.
    Inputs:  plan — the site's plan; vid — int or str (a VLAN ID as typed).
    Returns: (vlan, subnet or None).
    Fails:   ValidationError "VLAN <id> is not in <site>'s plan" (or not a number).
    Feeds:   set_vlan, remove_vlan, add_range, remove_range, add_address."""
    try:
        vid = int(str(vid).strip())
    except ValueError:
        raise ValidationError(f"VLAN {vid!r}: a VLAN ID, 1 to 4094")
    vlan = next((x for x in plan["vlans"] if x["id"] == vid), None)
    if vlan is None:
        raise ValidationError(f"VLAN {vid} is not in {plan['site']}'s plan")
    return vlan, next((s for s in plan["subnets"] if s.get("vlan") == vid), None)


def find_address(plan, ip):
    """Purpose: an address recorded in the site's plan and its subnet.
    Inputs:  plan — the site's plan; ip — str as typed.
    Returns: (address, subnet).
    Fails:   ValidationError: not an IPv4 address, or not recorded in <site>'s plan.
    Feeds:   set_address, remove_address."""
    want = str(ipv4(ip, "address"))
    for s in plan["subnets"]:
        for a in s.get("addresses") or []:
            if a["ip"] == want:
                return a, s
    raise ValidationError(f"{want} is not recorded in {plan['site']}'s plan")
