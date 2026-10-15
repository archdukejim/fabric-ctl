import ipaddress
import socket
import subprocess


def detect_network():
    """Purpose: best guesses for this host's network settings, used as prompt defaults.
    Inputs:  none (runs `ip -4 route show default` and `ip -o -4 addr show dev <iface>`; socket.gethostname()).
    Returns: {"hostname", "host_ip", "lan_gateway", "lan_cidr", "interface"} from the interface carrying the
             default route; values that cannot be found are None.
    Fails:   FileNotFoundError if the `ip` command is missing; a failing `ip` just yields None values.
    Feeds:   collect_vars (defaults for required values), setup/advanced/setup_menu (the values it shows as found)."""
    guess = {"hostname": socket.gethostname().split(".")[0], "host_ip": None,
             "lan_gateway": None, "lan_cidr": None, "interface": None}
    route = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True).stdout.split()
    if "via" in route:
        guess["lan_gateway"] = route[route.index("via") + 1]
    dev = route[route.index("dev") + 1] if "dev" in route else None
    guess["interface"] = dev
    if dev:
        addr = subprocess.run(["ip", "-o", "-4", "addr", "show", "dev", dev], capture_output=True,
                              text=True).stdout.split()
        if "inet" in addr:
            iface = ipaddress.ip_interface(addr[addr.index("inet") + 1])
            guess["host_ip"] = str(iface.ip)
            guess["lan_cidr"] = str(iface.network)
    return guess
