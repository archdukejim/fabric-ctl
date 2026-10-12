import ipaddress
import subprocess


def network_problem(data):
    """Purpose: what is wrong with the network's answers taken together (each one valid on its own).
    Inputs:  data — settings: host_ip, lan_cidr, lan_gateway.
    Returns: str, the problem; "" when they fit: the host and the gateway inside the subnet, neither its network nor
             its broadcast address, the gateway not the host, and the host's address one this machine has (the domain
             controller and nginx bind to it).
    Fails:   never (`ip` missing: this machine's addresses are not checked).
    Feeds:   setup/collect_vars, setup/advanced/ask_network and the menu's Proceed check."""
    host, net = ipaddress.IPv4Address(data["host_ip"]), ipaddress.IPv4Network(data["lan_cidr"], strict=False)
    gw = ipaddress.IPv4Address(data["lan_gateway"])
    for name, ip in (("this host's address", host), ("the gateway", gw)):
        if ip not in net:
            return f"{name} {ip} is not in the subnet {net}"
        if net.prefixlen < 31 and ip in (net.network_address, net.broadcast_address):
            return f"{name} {ip} is the subnet's network or broadcast address"
    if host == gw:
        return f"this host's address and the gateway are both {host}"
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True).stdout
    except FileNotFoundError:
        return ""
    mine = {f.split("/")[0] for line in out.splitlines() for f in line.split()[3:4]}
    if mine and str(host) not in mine:
        return f"{host} is not an address of this machine (it has {', '.join(sorted(mine - {'127.0.0.1'}))})"
    return ""
