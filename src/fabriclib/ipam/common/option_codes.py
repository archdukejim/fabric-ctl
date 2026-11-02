"""The DHCPv4 options by their Kea names and codes, one list for the address manager (manual 1.10.4.6.1: an option is
always shown with its standard name and its code; 1.10.4.24: the options an administrator may set), and the ones
fabric provides itself (1.10.4.6.2). Kea 3.0's standard option definitions (Kea ARM 3.0, "List of standard DHCPv4
options configurable by an administrator"; checked 2026-10-12, notes 2.3.10.7.3). The Networks tab's and the options
page's two copies were merged into this one at the 0.8.0 merge (2.3.10.5.5)."""

# Kea 3.0's standard DHCPv4 options an administrator may set, by code
CATALOGUE = {
    2: "time-offset", 3: "routers", 4: "time-servers", 5: "name-servers", 6: "domain-name-servers", 7: "log-servers",
    8: "cookie-servers", 9: "lpr-servers", 10: "impress-servers", 11: "resource-location-servers", 13: "boot-size",
    14: "merit-dump", 15: "domain-name", 16: "swap-server", 17: "root-path", 18: "extensions-path",
    19: "ip-forwarding", 20: "non-local-source-routing", 21: "policy-filter", 22: "max-dgram-reassembly",
    23: "default-ip-ttl", 24: "path-mtu-aging-timeout", 25: "path-mtu-plateau-table", 26: "interface-mtu",
    27: "all-subnets-local", 28: "broadcast-address", 29: "perform-mask-discovery", 30: "mask-supplier",
    31: "router-discovery", 32: "router-solicitation-address", 33: "static-routes", 34: "trailer-encapsulation",
    35: "arp-cache-timeout", 36: "ieee802-3-encapsulation", 37: "default-tcp-ttl", 38: "tcp-keepalive-interval",
    39: "tcp-keepalive-garbage", 40: "nis-domain", 41: "nis-servers", 42: "ntp-servers",
    43: "vendor-encapsulated-options", 44: "netbios-name-servers", 45: "netbios-dd-server", 46: "netbios-node-type",
    47: "netbios-scope", 48: "font-servers", 49: "x-display-manager", 52: "dhcp-option-overload",
    54: "dhcp-server-identifier", 56: "dhcp-message", 57: "dhcp-max-message-size", 60: "vendor-class-identifier",
    62: "nwip-domain-name", 63: "nwip-suboptions", 64: "nisplus-domain-name", 65: "nisplus-servers",
    66: "tftp-server-name", 67: "boot-file-name", 68: "mobile-ip-home-agent", 69: "smtp-server", 70: "pop-server",
    71: "nntp-server", 72: "www-server", 73: "finger-server", 74: "irc-server", 75: "streettalk-server",
    76: "streettalk-directory-assistance-server", 77: "user-class", 78: "slp-directory-agent",
    79: "slp-service-scope", 85: "nds-servers", 86: "nds-tree-name", 87: "nds-context",
    88: "bcms-controller-names", 89: "bcms-controller-address", 93: "client-system", 94: "client-ndi",
    97: "uuid-guid", 98: "uap-servers", 99: "geoconf-civic", 100: "pcode", 101: "tcode", 108: "v6-only-preferred",
    112: "netinfo-server-address", 113: "netinfo-server-tag", 114: "v4-captive-portal", 116: "auto-config",
    117: "name-service-search", 119: "domain-search", 121: "classless-static-route", 122: "cablelabs-client-conf",
    124: "vivco-suboptions", 125: "vivso-suboptions", 136: "pana-agent", 137: "v4-lost", 138: "capwap-ac-v4",
    141: "sip-ua-cs-domains", 143: "v4-sztp-redirect", 146: "rdnss-selection", 159: "v4-portparams",
    162: "v4-dnr", 212: "option-6rd", 213: "v4-access-domain",
}
CODES = {name: code for code, name in CATALOGUE.items()}
# the options fabric sets because it runs the service: marked "provided by fabric" (2.1.10.14, manual 1.10.4.6.2),
# by code; the subnet's gateway as its router is fabric's too, shown with a source of its own (effective_options)
FABRIC_PROVIDED = {6, 15, 42, 119}
