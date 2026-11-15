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

from fabriclib.ipam.rules.access_sources import access_sources


def _published_ports(v):
    """Purpose: the ports fabric's containers publish, by the service of the site's access rules that reaches them
             (manual 1.10.4.48.2): matched on the port the client asked for (conntrack's original destination port,
             before Docker's DNAT).
    Inputs:  v — fabric vars (bind_dns_port, default 53).
    Returns: {"dns": [(proto, port), ...], "web": [...], "radius": [...]}: each pair once.
    Fails:   never.
    Feeds:   apply_docker_firewall."""
    bind = str(v.get("bind_dns_port") or 53)
    dns = [("udp", "53"), ("tcp", "53"), ("tcp", "853"), ("udp", bind), ("tcp", bind)]
    return {"dns": list(dict.fromkeys(dns)), "web": [("tcp", "80"), ("tcp", "443")],
            "radius": [("udp", "1812"), ("udp", "1813")]}


def _rules(sources, ports, extra=(), radius_sources=()):
    """Purpose: the DOCKER-USER rules, in order (manual 1.10.4.48.3).
    Inputs:  sources — access_sources' result ({service: [CIDR, ...]}); ports — _published_ports' result; extra —
             security.firewall_allow (every published port, an explicit relaxation outside the rules);
             radius_sources — RADIUS client addresses (the switches and access points: RADIUS ports only).
    Returns: list of iptables rule argument lists: established traffic, traffic from docker0 and br-* bridges,
             each extra CIDR, each (network allowed a service, that service's ports), each RADIUS client return;
             any other NEW connection is dropped, with no reply.
    Fails:   never.
    Feeds:   apply_docker_firewall."""
    rules = [["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"],
             # traffic originating from containers (fabric_net or any other bridge)
             ["-i", "docker0", "-j", "RETURN"],
             ["-i", "br-+", "-j", "RETURN"]]
    rules += [["-s", cidr, "-j", "RETURN"] for cidr in extra]
    for service, pairs in ports.items():
        rules += [["-s", cidr, "-p", proto, "-m", "conntrack", "--ctorigdstport", port, "-j", "RETURN"]
                  for cidr in sources.get(service) or [] if ":" not in cidr for proto, port in pairs]
    # RADIUS clients (switches, APs) may sit outside the site's networks: RADIUS ports only
    rules += [["-s", src, "-p", "udp", "-m", "multiport", "--dports", "1812,1813", "-j", "RETURN"]
              for src in radius_sources]
    rules.append(["-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"])
    return rules


def _ipv6():
    """Purpose: the IPv6 DOCKER-USER chain, where Docker has one: fabric serves no IPv6 (2.1.10.54), so only
             established traffic and the containers' own pass; every new connection is dropped.
    Inputs:  none.
    Returns: bool: the chain was there and is filled.
    Fails:   CalledProcessError from ip6tables once the chain is known to be there.
    Feeds:   apply_docker_firewall."""
    if subprocess.run(["ip6tables", "-L", "DOCKER-USER", "-n"], capture_output=True).returncode != 0:
        return False
    subprocess.run(["ip6tables", "-F", "DOCKER-USER"], check=True)
    for rule in (["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"],
                 ["-i", "docker0", "-j", "RETURN"], ["-i", "br-+", "-j", "RETURN"],
                 ["-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"]):
        subprocess.run(["ip6tables", "-A", "DOCKER-USER", *rule], check=True)
    return True


def apply_docker_firewall(vars_file):
    """Purpose: flush and rebuild DOCKER-USER so a published port is reached only from the networks the site's access
             rules allow its service (dns, web, radius: manual 1.10.4.48.3), security.firewall_allow, and RADIUS
             clients (802.1X) on FreeRADIUS's ports; every other new connection is dropped with no reply, IPv6's too.
    Inputs:  vars_file — rendered vars.yaml: security.firewall (default True), security.firewall_allow,
             access_sources (or host_ip, lan_cidr and the plan last read), bind_dns_port, install_freeradius,
             radius_clients (IPv4 addresses; IPv6 skipped).
    Returns: a summary str: what each service is reached from, or "disabled" when security.firewall is false
             (chain flushed to a single RETURN).
    Fails:   OSError/yaml errors reading vars_file; CalledProcessError from iptables.
    Feeds:   configure_firewall.run (setup) and fabric-firewall.service at boot (`python3 -m ...`, prints it).
    Notes:   UFW cannot filter these ports: Docker routes them through its own chains before INPUT."""
    with open(vars_file) as f:
        v = yaml.safe_load(f) or {}
    security = v.get("security") or {}
    if not security.get("firewall", True):
        subprocess.run(["iptables", "-F", "DOCKER-USER"], capture_output=True)
        subprocess.run(["iptables", "-A", "DOCKER-USER", "-j", "RETURN"], capture_output=True)
        return "disabled"
    sources = access_sources(v)
    extra = list(dict.fromkeys(security.get("firewall_allow") or []))
    if subprocess.run(["iptables", "-L", "DOCKER-USER", "-n"], capture_output=True).returncode != 0:
        subprocess.run(["iptables", "-N", "DOCKER-USER"], check=True)
    subprocess.run(["iptables", "-F", "DOCKER-USER"], check=True)
    radius = [c["address"] for c in v.get("radius_clients") or []
              if v.get("install_freeradius") and ":" not in str(c.get("address", ""))]
    for rule in _rules(sources, _published_ports(v), extra, radius):
        subprocess.run(["iptables", "-A", "DOCKER-USER", *rule], check=True)
    six = _ipv6()
    said = "; ".join(f"{s} from {', '.join(sources.get(s) or []) or 'no network'}" for s in ("dns", "web", "radius"))
    return (f"published ports: {said}" + (f"; every port from {', '.join(extra)}" if extra else "")
            + ("; IPv6: no new connection" if six else ""))


if __name__ == "__main__":
    print(apply_docker_firewall(sys.argv[1]))
