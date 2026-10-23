"""What the router g23-vm-rtr-1 runs (manual 3.1.5.7, decision 2.1.1.65): its netplan, nftables NAT, forwarding, and
a DHCP relay to fabric that is installed but left disabled.

Purpose: the router's part of its autoinstall user-data.
Inputs: the inventory and the router's VM entry.
Returns: (netplan network dict, extra packages, late-commands).
Fails: never.
Feeds: ubuntu_seed.py.
"""
import base64

from lab_inventory import mac

_NFT = """#!/usr/sbin/nft -f
# fabric lab router (manual 3.1.5.7): NAT for the lab and its VLANs out of wan; nothing comes in from wan.
flush ruleset
table inet fabric_lab {
    set inside { type ifname; elements = { "lab", "vlans.10", "vlans.20", "vlans.30" } }
    chain input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        ct state established,related accept
        ct state invalid drop
        iifname @inside accept
        ip protocol icmp accept
        meta l4proto ipv6-icmp accept
        iifname "wan" udp dport 68 accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname @inside oifname "wan" accept
        iifname @inside oifname @inside accept
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "wan" ip saddr { 10.88.0.0/24, 10.88.10.0/24, 10.88.20.0/24, 10.88.30.0/24 } masquerade
    }
}
"""

_SYSCTL = "# fabric lab router (manual 3.1.5.7)\nnet.ipv4.ip_forward = 1\n"

# isc-dhcp-relay's settings, ready for 0.9.0's DHCP tests; the service stays disabled until then (3.1.5.7)
_RELAY = ('# fabric lab router (manual 3.1.5.7): relays to fabric; disabled until fabric\'s DHCP is tested\n'
          'SERVERS="10.88.0.10"\nINTERFACES="lab vlans.10 vlans.20 vlans.30"\nOPTIONS=""\n')


def _write(path, text, mode):
    b64 = base64.b64encode(text.encode()).decode()
    return [f"echo {b64} | base64 -d > /target{path}", f"chmod {mode} /target{path}"]


def router_config(inv, vm):
    net = {
        "version": 2,
        "ethernets": {
            "lab": {"match": {"macaddress": mac(vm, 1)}, "set-name": "lab",
                    "addresses": [vm["ip"] + "/24"], "nameservers": {"addresses": [inv["network"]["dns"]]}},
            "wan": {"match": {"macaddress": mac(vm, 3)}, "set-name": "wan", "dhcp4": True},
            "vlans": {"match": {"macaddress": mac(vm, 2)}, "set-name": "vlans", "dhcp4": False},
        },
        "vlans": {f"vlans.{v}": {"id": v, "link": "vlans", "addresses": [f"10.88.{v}.1/24"]}
                  for v in inv["vlans"]},
    }
    late = []
    late += _write("/etc/nftables.conf", _NFT, "0644")
    late += _write("/etc/sysctl.d/90-fabric-lab-router.conf", _SYSCTL, "0644")
    late += ["curtin in-target -- systemctl enable nftables.service"]
    # the relay: installed, configured, never started here (no DHCP server or relay runs before 0.9.0's tests)
    late += ["curtin in-target -- env DEBIAN_FRONTEND=noninteractive apt-get install -y isc-dhcp-relay"]
    late += _write("/etc/default/isc-dhcp-relay", _RELAY, "0644")
    late += ["curtin in-target -- systemctl disable isc-dhcp-relay.service",
             "curtin in-target -- systemctl mask isc-dhcp-relay.service"]
    return net, ["nftables"], late
