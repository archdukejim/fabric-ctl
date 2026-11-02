import ipaddress

from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.normalize_dhcp import LABEL_RE
from fabriclib.ipam.common.fields import host_in, ipv4, notes, one_line


def _overlap_message(net, other):
    """Purpose: the refusal for a subnet that overlaps another network (manual 1.10.4.3.2).
    Inputs:  net — the new subnet; other — {"cidr", "name", "site"}.
    Returns: str.
    Fails:   never.
    Feeds:   check_subnet."""
    return (f"{net} overlaps {other['cidr']} ({other.get('name') or 'a network'}) of site {other['site']}. Choose "
            "another network, or give --allow-overlap \"<why>\" if the two are never routed together")


def check_subnet(subnet, plan, site, networks, fabric_subnet="10.255.0.0/24", current=None):
    """Purpose: a subnet of a site's plan checked against the model's rules (manual 1.10.4.3): an IPv4 network with
             room for hosts, a name unique in the site, a gateway that is one of its hosts, a relay address, and no
             overlap with another network anywhere in the organisation (1.10.2.6) unless either side gives a reason
             (--allow-overlap), nor ever with fabric's own container network.
    Inputs:  subnet — {"name", "cidr", "vlan", "gateway", "dhcp", "relay", "notes", "allow_overlap"}; plan — the site's
             plan (read_plan: "subnets"); site — the site's name; networks — every site's networks (read_address_plan:
             [{"site", "name", "cidr", "kind", "allow_overlap"}], the plan's subnets among them); fabric_subnet —
             fabric's container network; current — the name of the subnet being changed (its own entries are not
             an overlap), None for a new one.
    Returns: the subnet normalized: {"name", "cidr" (str), "vlan", "gateway" ("" for none), "dhcp" (bool), "relay",
             "notes", "allow_overlap"}.
    Fails:   ValidationError: not an IPv4 network (host bits set included) or smaller than /30, a name that is not one
             DNS label or another subnet's in the site, a gateway that is not a host of it, a relay that is not an
             IPv4 address, an overlap with fabric_subnet, an overlap with another network without a reason (named,
             with its site), notes or reason too long.
    Feeds:   add_vlan, set_vlan."""
    try:
        net = ipaddress.ip_network(str(subnet.get("cidr") or "").strip(), strict=True)
    except ValueError:
        raise ValidationError(f"subnet {subnet.get('cidr')!r}: a network like 10.1.20.0/24 (host bits zero)")
    if net.version != 4 or net.prefixlen > 30:
        raise ValidationError(f"subnet {net}: an IPv4 network of at least four addresses (/30 or larger)")
    name = str(subnet.get("name") or "").strip().lower()
    if not LABEL_RE.match(name):
        raise ValidationError(f"subnet name {subnet.get('name')!r} is one DNS label")
    if any(s["name"] == name and s["name"] != current for s in plan.get("subnets") or []):
        raise ValidationError(f"the subnet name {name} is already used in this site")
    gateway = ""
    if subnet.get("gateway"):
        addr = ipv4(subnet["gateway"], "gateway")
        host_in(addr, net, "gateway")
        gateway = str(addr)
    relay = str(ipv4(subnet["relay"], "relay")) if subnet.get("relay") else ""
    reason = one_line(subnet.get("allow_overlap"), "the overlap reason")
    if net.overlaps(ipaddress.ip_network(str(fabric_subnet or "10.255.0.0/24"), strict=False)):
        raise ValidationError(f"{net} overlaps fabric's own container network {fabric_subnet} (fabric_subnet): "
                              "clients there could not reach this site's services")
    for other in networks:
        if other["site"] == site and current and other["name"] == current:
            continue
        if other["site"] == site and other.get("kind") == "lan" and other["cidr"] == str(net):
            continue                       # the site's own LAN, served as this VLAN
        if not net.overlaps(ipaddress.ip_network(other["cidr"], strict=False)):
            continue
        if reason or other.get("allow_overlap"):
            continue
        raise ValidationError(_overlap_message(net, other))
    return {"name": name, "cidr": str(net), "vlan": subnet.get("vlan"), "gateway": gateway,
            "dhcp": bool(subnet.get("dhcp")), "relay": relay, "notes": notes(subnet.get("notes")),
            "allow_overlap": reason}
