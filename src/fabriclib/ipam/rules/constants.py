"""The access table's words (manual 1.10.4.48.10, 1.10.4.48.2): the services with their ports, the networks that
are not VLANs, the actions."""

# each service, in the order they are shown, with its ports as people read them (2.1.10.55)
SERVICES = {
    "dns": "53/udp, 53/tcp, 853/tcp; BIND's bind_dns_port",
    "ntp": "123/udp",
    "dhcp": "67/udp",
    "web": "80/tcp, 443/tcp",
    "ad": "88, 135, 389, 445, 464, 636, 3268, 3269/tcp; 88, 389, 464/udp; ad_rpc_ports",
    "radius": "1812/udp, 1813/udp",
    "ssh": "sshd's ports",
    "ping": "ICMP echo",
}
FABRIC = "fabric"           # every network of the domain's other sites (2.1.10.63)
ANY = "any"                 # every other IPv4 address, outside ones too (2.1.10.63)
ALL = "all"                 # every service at once, on the command line
EXTERNAL = "0.0.0.0/0"      # what `any` stands for
ACTIONS = ("allow", "deny")

# what the host's VLAN must keep, unless --force at the host (2.1.10.57)
GUARDED = ("ssh", "web")
