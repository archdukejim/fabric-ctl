"""Filter traffic to Docker-published ports (DOCKER-USER chain).

UFW cannot do this: Docker routes published ports through its own
iptables chains before UFW's INPUT rules ever see them. DOCKER-USER is the
chain Docker reserves for exactly this; fabric owns its contents.

Run by `fabricctl setup` and at every boot by fabric-firewall.service:
    python3 -m fabriclib.security.apply_docker_firewall <vars.yaml>
"""
import subprocess
import sys

import yaml

from fabriclib.dhcp.client_networks import client_networks


GUEST_PORTS = "53,853"          # a guest subnet's clients reach the filtering resolver only (DNS, DoT: 2.1.10.4)


def _rules(allowed_cidrs, radius_sources=(), guest_cidrs=(), radsec_sources=()):
    """Purpose: the DOCKER-USER rules, in order.
    Inputs:  allowed_cidrs — sources that may open connections; radius_sources — RADIUS client addresses
             (allowed to UDP 1812/1813 only; default none); guest_cidrs — DHCP's guest subnets (to the published
             DNS ports only, matched on the port the client asked for: GUEST_PORTS); radsec_sources — RADIUS
             clients on RadSec (allowed to TCP 2083 only; manual 1.11.1.3).
    Returns: list of iptables rule argument lists: established traffic, traffic from docker0 and br-* bridges,
             each allowed CIDR and RADIUS source return; any other NEW connection is dropped.
    Fails:   never.
    Feeds:   apply_docker_firewall."""
    rules = [["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"],
             # traffic originating from containers (fabric_net or any other bridge)
             ["-i", "docker0", "-j", "RETURN"],
             ["-i", "br-+", "-j", "RETURN"]]
    rules += [["-s", cidr, "-j", "RETURN"] for cidr in allowed_cidrs]
    # RADIUS clients (switches, APs) may sit outside the LAN: RADIUS ports only
    rules += [["-s", src, "-p", "udp", "-m", "multiport", "--dports", "1812,1813", "-j", "RETURN"]
              for src in radius_sources]
    rules += [["-s", src, "-p", "tcp", "--dport", "2083", "-j", "RETURN"] for src in radsec_sources]
    rules += [["-s", src, "-p", proto, "-m", "conntrack", "--ctorigdstport", port, "-j", "RETURN"]
              for src in guest_cidrs for proto in ("udp", "tcp") for port in GUEST_PORTS.split(",")
              if not (proto == "udp" and port == "853")]
    rules.append(["-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"])
    return rules


def apply_docker_firewall(vars_file):
    """Purpose: flush and rebuild DOCKER-USER so only the LAN, security.firewall_allow and DHCP's full subnets may
             open new connections to Docker-published ports, DHCP's guest subnets only to the DNS ports, and RADIUS
             clients (802.1X) only to FreeRADIUS's ports (2.1.10.4; TCP 2083 for RadSec clients, 1.11.1.3).
    Inputs:  vars_file — rendered vars.yaml: lan_cidr, security.firewall (default True),
             security.firewall_allow, install_kea + dhcp.subnets (client_networks), install_freeradius,
             radius_clients (IPv4 addresses, transport; IPv6 skipped).
    Returns: a summary str: "published ports limited to <cidrs>", or "disabled" when security.firewall is false
             (chain flushed to a single RETURN).
    Fails:   OSError/yaml errors reading vars_file; KeyError without lan_cidr; CalledProcessError from iptables.
    Feeds:   configure_firewall.run (setup) and fabric-firewall.service at boot (`python3 -m ...`, prints it).
    Notes:   UFW cannot filter these ports: Docker routes them through its own chains before INPUT."""
    with open(vars_file) as f:
        v = yaml.safe_load(f) or {}
    security = v.get("security") or {}
    if not security.get("firewall", True):
        subprocess.run(["iptables", "-F", "DOCKER-USER"], capture_output=True)
        subprocess.run(["iptables", "-A", "DOCKER-USER", "-j", "RETURN"], capture_output=True)
        return "disabled"
    dhcp = client_networks(v)
    allowed = list(dict.fromkeys([v["lan_cidr"], *(security.get("firewall_allow") or []), *dhcp["full"]]))
    if subprocess.run(["iptables", "-L", "DOCKER-USER", "-n"], capture_output=True).returncode != 0:
        subprocess.run(["iptables", "-N", "DOCKER-USER"], check=True)
    subprocess.run(["iptables", "-F", "DOCKER-USER"], check=True)
    radius = [c for c in v.get("radius_clients") or []
              if v.get("install_freeradius") and ":" not in str(c.get("address", ""))]
    radsec = [c["address"] for c in radius if c.get("transport") == "radsec"]
    for rule in _rules(allowed, [c["address"] for c in radius], dhcp["guest"], radsec):
        subprocess.run(["iptables", "-A", "DOCKER-USER", *rule], check=True)
    guests = f"; DNS only from {', '.join(dhcp['guest'])}" if dhcp["guest"] else ""
    return f"published ports limited to {', '.join(allowed)}{guests}"


if __name__ == "__main__":
    print(apply_docker_firewall(sys.argv[1]))
