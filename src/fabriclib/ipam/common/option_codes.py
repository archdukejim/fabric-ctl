"""The standard DHCPv4 options by their Kea names and codes (manual 1.10.4.6.1: an option is always shown with its
standard name and its code), and the ones fabric provides itself (1.10.4.6.2). The names and codes are Kea 3.0's
standard option definitions (Kea ARM, "Standard DHCPv4 Options"; checked 2026-10-12, notes 2.3.10.7)."""

CODES = {
    "subnet-mask": 1, "time-offset": 2, "routers": 3, "time-servers": 4, "name-servers": 5,
    "domain-name-servers": 6, "log-servers": 7, "host-name": 12, "domain-name": 15, "root-path": 17,
    "interface-mtu": 26, "broadcast-address": 28, "static-routes": 33, "ntp-servers": 42,
    "vendor-encapsulated-options": 43, "netbios-name-servers": 44, "dhcp-lease-time": 51,
    "vendor-class-identifier": 60, "tftp-server-name": 66, "boot-file-name": 67, "user-class": 77,
    "client-system": 93, "v4-captive-portal": 114, "domain-search": 119, "classless-static-route": 121,
}
NAMES = {code: name for name, code in CODES.items()}
# what fabric sets itself because it runs the service (1.10.4.6.2): DNS, NTP, the domain and its search list, and
# the subnet's gateway as its router
PROVIDED = ("routers", "domain-name-servers", "ntp-servers", "domain-name", "domain-search")
