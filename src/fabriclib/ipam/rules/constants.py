"""The access rules' words (manual 1.10.4.48.1, 1.10.4.48.2): the services with their ports, the actions, the
fresh site's rule list."""

# each service a rule may name, in the order they are shown, with its ports as people read them (2.1.10.55)
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
ANY = "any"
HOST = "host"
ACTIONS = ("allow", "deny")

# what a fresh site has (2.1.10.53): only the host's own VLAN reaches fabric
DEFAULT_RULES = [{"from": HOST, "service": ANY, "action": "allow"}]

# what the host's VLAN must keep, unless --force at the host (2.1.10.57)
GUARDED = ("ssh", "web")
