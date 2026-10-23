"""What the pages show: the navigation, sections, sub-menus, the permissions that show them."""

# Apply per page (manual 1.8.6.5): fabric-agent's pending page ids -> the navigation page whose changes they are
PENDING_PAGES = {"people": "/directory/people", "groups": "/directory/groups", "machines": "/directory/computers",
                 "policies": "/directory/policies", "ous": "/directory/ous", "access": "/directory/access",
                 "kerberos": "/directory/kerberos", "account": "/account/groups"}

# The navigation down the left (manual 1.8.6.4): (entry id, label, its pages); a page is (path, label, the
# permissions that show it: any one of them; () = any signed-in person). An entry shows when one of its pages does.
NAV = [
    ("overview", "Overview", [("/", "Health", ("status:read",)), ("/overview/doctor", "Doctor", ("status:read",)),
                              ("/overview/updates", "Updates", ("status:read",)),
                              ("/audit", "Audit log", ("audit:read",))]),
    ("account", "My account", [("/account", "My account", ()), ("/account/groups", "Groups I manage", ())]),
    ("dns", "DNS", [("/dns/zones", "Zones", ("dns:read",)),
                    ("/dns-filter", "DNS filter", ("dns:filter", "dns:querylog"))]),
    ("dhcp", "DHCP", [("/kea", "Kea", ("dhcp:read",))]),
    ("pki", "PKI", [("/pki", "Certificates", ("pki:read",)), ("/pki/acme", "ACME", ("pki:read",))]),
    ("directory", "Directory", [("/directory", "Overview", ("domain:read",)),
                                ("/directory/people", "People", ("people:read",)),
                                ("/directory/groups", "Groups", ("domain:read",)),
                                ("/directory/computers", "Computers", ("domain:read",)),
                                ("/directory/ous", "OUs", ("domain:read",)),
                                ("/directory/sites", "Sites", ("domain:read",)),
                                ("/directory/access", "Access", ("domain:read",)),
                                ("/directory/kerberos", "Kerberos", ("domain:read",)),
                                ("/directory/policies", "Policies", ("domain:read",))]),
    ("8021x", "802.1X", [("/8021x", "RADIUS clients", ("radius:read",)),
                         ("/8021x/devices", "Devices", ("devices:read",)),
                         ("/8021x/roles", "Device roles", ("devices:read",)),
                         ("/8021x/decisions", "Recent decisions", ("radius:read",)),
                         ("/8021x/guides", "Setup guides", ("radius:read",))]),
    ("secrets", "Secrets", [("/secrets", "Status", ("vault:status",)),
                            ("/secrets/unlock", "Unlock methods", ("vault:status",)),
                            ("/secrets/disk", "Disk encryption", ("vault:status",))]),
    ("federation", "Federation", [("/federation", "Sites and replication", ("federation:read",))]),
    ("settings", "Settings", [("/settings", "Setup wizard", ("settings:admin",)),
                              ("/settings/sign-in", "Sign-in security", ("security:raise",))]),
]
# DNS filter tab sections: (view, label); the query log needs dns:querylog (MENU_PERMS)
DNS_FILTER_SECTIONS = [("overview", "Overview"), ("lists", "Lists"), ("rules", "Rules"), ("groups", "Groups"),
                       ("querylog", "Query log"), ("settings", "Settings")]
# BIND9 tab sections: (view, label)
FREERADIUS_SECTIONS = [("switches", "Connect a switch"), ("windows", "Connect Windows")]   # 802.1X → Setup guides
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
# Directory · Kerberos' ticket policy (1.6.12.9): (key, label, lowest, highest); the agent checks the whole policy
KERBEROS_FIELDS = [("ticket_hours", "Maximum ticket age (hours)", 1, "the renewal age"),
                   ("renew_days", "Maximum renewal age (days)", 1, 30),
                   ("skew_minutes", "Clock skew allowed (minutes)", 1, 15)]
# Directory tab sections: (view, label)
DIRECTORY_SECTIONS = [("devices", "Devices"), ("roles", "Roles"), ("people", "People"), ("domain", "Domain"),
                      ("machines", "Machines"), ("gpo", "Group Policy")]
# Step-CA tab sub-menu: (view, label)
STEPCA_MENU = [("ca", "Certificate authority"), ("sign", "Sign a CSR"), ("issue", "New key + certificate"),
               ("inspect", "Inspect"), ("convert", "Convert"), ("issued", "Issued"),
               ("acme", "ACME")]
STEPCA_VIEWS = {v for v, _ in STEPCA_MENU}
KEY_TYPES = ["RSA-2048", "RSA-3072", "RSA-4096", "EC-P256", "EC-P384"]
TSIG_SCOPES = [("acme-hosts", "Certbot DNS-01 for listed hosts only (TXT)"),
               ("acme-zone", "Certbot DNS-01 for any host in the zone (TXT)"),
               ("any-name", "Any name in the zone, chosen record types")]
TSIG_ANY_TYPES = ["A", "AAAA", "CNAME", "TXT", "SRV", "MX"]
# service -> (what it is, its page)
SERVICES = {
    "nginx": ("Reverse proxy", None), "bind9": ("DNS", "/dns/zones"), "stepca": ("Certificate authority", "/pki"),
    "postgres": ("Keycloak database", None),
    "keycloak": ("Single sign-on", None), "openbao": ("Secrets", "/secrets"), "kea": ("DHCP", "/kea"),
    "freeradius": ("802.1X", "/8021x"), "samba": ("Directory (Samba AD)", "/directory/people"),
    "fabric-web": ("This web UI", None), "fabric-agent": ("Host API", None),
}
# every permission a page asks about (the dev preview's fallback when it runs without fabriclib)
PREVIEW_PERMS = ["status:read", "dns:read", "dns:write", "tsig:manage", "dhcp:read", "dhcp:write", "pki:read",
                 "pki:issue", "pki:sign",
                 "pki:link-device", "devices:read", "devices:enroll", "devices:admin", "roles:admin", "radius:read",
                 "radius:admin",
                 "people:read", "domain:read", "domain:admin", "machines:admin", "sudo:admin", "gpo:admin",
                 "federation:read",
                 "vault:status", "vault:unlock", "audit:read", "dns:filter", "dns:querylog", "settings:admin"]
MENU_PERMS = {"sign": "pki:sign", "issue": "pki:issue", "convert": "pki:issue", "people": "people:read",
              "devices": "devices:read", "roles": "devices:read", "unlock": "vault:status", "disk": "vault:status",
              "domain": "domain:read", "machines": "domain:read", "gpo": "domain:read", "querylog": "dns:querylog",
              "lists": "dns:filter", "rules": "dns:filter", "settings": "dns:filter"}
# the setup wizard's steps (manual 1.8.5.3): (step, title, its fields); the fields are agent settings_from_form's
WIZARD_STEPS = [
    ("parts", "Optional parts", ["dns_filter", "install_fluentbit", "log_target"]),
    ("memory", "Memory", ["host_ram_capacity"]),
    ("signin", "Passwords and sign-in", ["policy_" + k for k, _ in POLICY_FIELDS]
     + ["policy_complexity", "signin_kerberos"]),
    ("upstreams", "The DNS filter's upstreams", ["dns_filter_upstreams"]),
    ("review", "Review", []),
]
WIZARD_FIELDS = [f for _, _, fields in WIZARD_STEPS for f in fields]
# the navigation page each sectioned view belongs to (manual 1.8.6.4)
DIRECTORY_PAGES = {"devices": "/8021x/devices", "device": "/8021x/devices", "roles": "/8021x/roles",
                   "role": "/8021x/roles", "people": "/directory/people", "overview": "/directory"}
# Directory · Policies' kinds (1.6.12.10): (view, label), all on Policies' one Apply
POLICY_SECTIONS = [("password", "Password policy"), ("gpo", "Group Policy"), ("sudo", "Sudo rules")]
# a person's details (2.1.6.93's fields) in order, with their labels: My account and a person's page and Edit form
PERSON_FIELDS = (("first", "First name"), ("last", "Last name"), ("name", "Display name"), ("email", "E-mail"),
                 ("phone", "Phone"), ("mobile", "Mobile"), ("title", "Title"), ("department", "Department"),
                 ("company", "Company"), ("office", "Office"), ("city", "City"), ("state", "State"),
                 ("country", "Country"), ("manager", "Manager"), ("employee_id", "Employee ID"))
PER_PAGE = 50                            # a long list's page (1.8.6.3): People, Groups, Computers
# Directory · Computers (1.6.12.6): a computer's types (its folder and type group, 1.6.13.3) and the page's tabs
COMPUTER_TYPES = {"server": "Server", "desktop": "Desktop", "network": "Network"}
COMPUTER_SECTIONS = [("list", "Computers"), ("groups", "Machine groups")]
# Directory · OUs (1.6.12.7): the folders an admin's own OUs go under (and under their own there), as the DC has them
# Directory · Access (1.6.13.4): a grant's categories of rights with switches, (field, label, its rights); sudo and
# local administrator are their own switches
GRANT_RIGHTS = (("people", "People", ("edit", "reset", "unlock", "disable", "add")),
                ("machines", "Machines", ("add", "move", "disable", "remove", "groups")),
                ("signin", "Sign-in", ("keyboard", "remote")))
OU_ROOTS = ("people", "service-accounts", "groups", "machines/servers", "machines/desktops", "machines/network")
RADIUS_PAGES = {"overview": "/8021x", "decisions": "/8021x/decisions", "switches": "/8021x/guides",
                "windows": "/8021x/guides"}
JOB_PAGES = {"doctor": "/overview/doctor", "images": "/overview/updates", "settings": "/settings"}
# a group's kind (2.1.6.67, 1.6.12.17.5) -> (its label, why its members and managers are or are not changed here)
GROUP_KINDS = {
    "own": ("the site's", ""),
    "bundle": ("a role bundle's", "Its members get the bundle's permissions in fabric."),
    "fabric": ("fabric's", "Fabric's own group: its members get permissions in fabric."),
    "tier": ("a tier's", "A tier's group: only the tier above it (fabric-admin) changes it."),
    "ad": ("AD's own", "Managed by fabric: AD's own groups are left as AD has them."),
    "computed": ("computed", "Managed by fabric: computed from the grants, never changed by hand."),
    "filled": ("filled by fabric", "Managed by fabric: fabric fills it."),
    "host-group": ("a machine group", "Its machines are changed on each computer's page."),
}
GROUP_FIXED = ("ad", "computed", "filled", "host-group")   # kinds that take no members and no managers here
