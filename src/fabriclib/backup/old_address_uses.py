import ipaddress

# fabric's own: rendered again from the new address by setup (manual 1.3.7.7), or the change itself
FOLLOWS = {"host_ip", "lan_cidr", "lan_gateway", "dns_fabric_own", "bind_acls"}


def _hits(value, old_ip, old_net):
    """Purpose: whether one setting's text names the old address, or an address or subnet inside the old subnet.
    Inputs:  value — a str; old_ip — IPv4Address; old_net — IPv4Network.
    Returns: True or False.
    Fails:   never.
    Feeds:   old_address_uses."""
    text = value.strip()
    try:
        if "/" in text:
            return ipaddress.ip_network(text, strict=False).overlaps(old_net)
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    return addr == old_ip or addr in old_net


def old_address_uses(v, old_ip, old_cidr):
    """Purpose: what still names the old address or subnet after a move to another one (manual 1.3.7.7): the admin's
             records, DHCP's subnets, routers and options, RADIUS clients, firewall allowances, extra certificates'
             names, the upstream DNS server; listed for the admin to change, never changed silently (2.1.4.6).
    Inputs:  v — vars.yaml as restored, with the new address; old_ip, old_cidr — the address and subnet it had.
    Returns: [(setting path such as "dns.lan.test.A.www", value)], in the file's order; [] when nothing does.
    Fails:   ValueError for an old address or subnet that is not one.
    Feeds:   restore_bundle (its report), run_restore_command and run_reinstall_command (printed)."""
    ip, net = ipaddress.ip_address(old_ip), ipaddress.ip_network(old_cidr, strict=False)
    found = []

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, path + [str(key)])
        elif isinstance(node, list):
            for i, value in enumerate(node):
                walk(value, path + [str(i)])
        elif isinstance(node, str) and _hits(node, ip, net):
            found.append((".".join(path), node))

    for key, value in v.items():
        if key not in FOLLOWS:
            walk(value, [key])
    return found
