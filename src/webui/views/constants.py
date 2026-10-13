"""What the pages show: tabs, sections, sub-menus, the permissions that show them."""

# (tab id, path, label, optional feature)
TABS = [
    ("overview", "/", "Overview", False),
    ("bind9", "/bind9", "BIND9 · DNS", False),
    ("networks", "/networks", "Networks", True),
    ("kea", "/kea", "Kea · DHCP", True),
    ("dnsfilter", "/dns-filter", "DNS filter", True),
    ("stepca", "/stepca", "Step-CA · PKI", False),
    ("directory", "/directory", "Directory", False),
    ("freeradius", "/freeradius", "FreeRADIUS · 802.1X", True),
    ("openbao", "/openbao", "OpenBao · Secrets", False),
    ("federation", "/federation", "Federation", False),
    ("security", "/security", "Security", False),
    ("ssh", "/ssh", "SSH", False),
]
# DNS filter tab sections: (view, label); the query log needs dns:querylog (MENU_PERMS)
DNS_FILTER_SECTIONS = [("overview", "Overview"), ("lists", "Lists"), ("rules", "Rules"), ("groups", "Groups"),
                       ("querylog", "Query log"), ("settings", "Settings")]
# BIND9 tab sections: (view, label)
FREERADIUS_SECTIONS = [("overview", "Overview"), ("sessions", "Sessions"), ("switches", "Connect a switch"),
                       ("windows", "Connect Windows")]
BIND9_SECTIONS = [("forward", "Forward zones"), ("landing", "Landing page"), ("reverse", "Reverse zones"),
                  ("dhcp", "DHCP names"),
                  ("tsig", "TSIG keys")]
# OpenBao tab sections and unlock-method (key slot) types
OPENBAO_SECTIONS = [("status", "Status"), ("unlock", "Unlock methods"), ("secrets", "Secrets"),
                    ("disk", "Disk encryption")]
OPENBAO_VIEWS = {"status", "unlock", "secrets", "disk", "add-security-key", "add-usb", "add-hsm", "rotate", "remove"}
SLOT_TYPES = {
    "local": ("Key file", "On this host's disk. Always present, so no kill switch."),
    "pkcs11": ("Security key", "YubiKey, Nitrokey, SmartCard-HSM or any PKCS#11 token. The key can't be copied."),
    "kmip": ("HSM / key manager", "Any KMIP server on your network. Revoke fabric there to lock the vault."),
    "security-key": ("Security key", "YubiKey, Nitrokey, SmartCard-HSM or any PKCS#11 token. The key can't be copied."),
    "usb": ("USB stick", "A plain or keypad-encrypted stick. Cheap; a plain stick can be copied."),
    "hsm": ("HSM / key manager", "Any KMIP server on your network. Revoke fabric there to lock the vault."),
}
# the password policy's form in the Domain section (2.1.2.22): (key, label); complexity is a choice of its own. The
# agent checks every value as `fabricctl domain password-policy` does (fabriclib.samba.check_password_policy).
POLICY_FIELDS = [("minimum_length", "Minimum length (characters)"), ("history", "Passwords remembered"),
                 ("minimum_age_days", "Changed again after (days)"),
                 ("maximum_age_days", "Valid for (days; 0: never expires)"),
                 ("lockout_threshold", "Failed sign-ins before a lockout (0: never)"),
                 ("lockout_minutes", "Locked for (minutes; 0: until an admin unlocks)"),
                 ("lockout_window_minutes", "Failed sign-ins forgotten after (minutes)")]
# Directory tab sections: (view, label)
DIRECTORY_SECTIONS = [("devices", "Devices"), ("roles", "Roles"), ("people", "People"), ("domain", "Domain"),
                      ("machines", "Machines"), ("gpo", "Group Policy")]
# Step-CA tab sub-menu: (view, label)
STEPCA_MENU = [("ca", "Certificate authority"), ("sign", "Sign a CSR"), ("issue", "New key + certificate"),
               ("inspect", "Inspect"), ("convert", "Convert"), ("issued", "Issued"),
               ("acme", "ACME"), ("enrol", "Enrol a device")]
STEPCA_VIEWS = {v for v, _ in STEPCA_MENU}
KEY_TYPES = ["RSA-2048", "RSA-3072", "RSA-4096", "EC-P256", "EC-P384"]
TSIG_SCOPES = [("acme-hosts", "Certbot DNS-01 for listed hosts only (TXT)"),
               ("acme-zone", "Certbot DNS-01 for any host in the zone (TXT)"),
               ("any-name", "Any name in the zone, chosen record types")]
TSIG_ANY_TYPES = ["A", "AAAA", "CNAME", "TXT", "SRV", "MX"]
# service -> (what it is, tab)
SERVICES = {
    "nginx": ("Reverse proxy", None), "bind9": ("DNS", "bind9"), "stepca": ("Certificate authority", "stepca"),
    "postgres": ("Keycloak database", None),
    "keycloak": ("Single sign-on", None), "openbao": ("Secrets", "openbao"), "kea": ("DHCP", "kea"),
    "freeradius": ("802.1X", "freeradius"), "samba": ("Directory (Samba AD)", "directory"),
    "fabric-web": ("This web UI", None), "fabric-agent": ("Host API", None),
}
# every permission a page asks about (the dev preview's fallback when it runs without fabriclib)
PREVIEW_PERMS = ["status:read", "dns:read", "dns:write", "tsig:manage", "dhcp:read", "dhcp:write", "dhcp:org-options",
                 "pki:read",
                 "pki:issue", "pki:sign", "pki:enrol",
                 "pki:link-device", "devices:read", "devices:enroll", "devices:admin", "roles:admin", "radius:read",
                 "radius:admin",
                 "people:read", "domain:read", "domain:admin", "machines:admin", "sudo:admin", "gpo:admin",
                 "federation:read",
                 "vault:status", "vault:unlock", "audit:read", "dns:filter", "dns:querylog"]
# tab -> the permission(s) that show it (any of them)
TAB_PERMS = {"overview": ("status:read",), "bind9": ("dns:read",), "kea": ("dhcp:read",), "networks": ("dhcp:read",),
             "stepca": ("pki:read",),
             "dnsfilter": ("dns:filter", "dns:querylog"),
             "directory": ("devices:read", "people:read", "domain:read"), "freeradius": ("radius:read",),
             "openbao": ("vault:status",), "federation": ("federation:read",),
             "security": ("security:raise",), "ssh": ("*",)}       # "*": any signed-in person (2.1.7.12)
MENU_PERMS = {"sign": "pki:sign", "issue": "pki:issue", "convert": "pki:issue", "people": "people:read",
              "devices": "devices:read", "roles": "devices:read", "unlock": "vault:status", "disk": "vault:status",
              "domain": "domain:read", "machines": "domain:read", "gpo": "domain:read", "querylog": "dns:querylog",
              "lists": "dns:filter", "rules": "dns:filter", "settings": "dns:filter", "enrol": "pki:enrol"}
