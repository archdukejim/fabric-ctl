# fabric-agent routes -> the permission they need. A route not listed here is
# refused (default deny). "session" = any signed-in fabric user.
GET = {
    ("version",): "session",
    ("services",): "status:read", ("host-changes",): "status:read", ("relaxed-settings",): "status:read",
    ("cert-warnings",): "status:read", ("images",): "status:read", ("jobs", "*"): "session",
    ("zones",): "dns:read", ("zones", "*"): "dns:read", ("reverse-zones",): "dns:read", ("tsig",): "dns:read",
    ("audit",): "audit:read",
    ("dhcp",): "dhcp:read",
    ("networks",): "dhcp:read", ("networks", "*"): "dhcp:read", ("networks", "*", "export"): "dhcp:read",
    ("ipam", "scan"): "dhcp:read",                     # the subnets a scan may cover (2.1.10.26)
    ("ipam", "options", "*"): "dhcp:read", ("ipam", "options", "*", "*"): "dhcp:read",
    ("dns-filter",): "dns:filter",
    ("radius",): "radius:read", ("radius", "guides"): "radius:read", ("radius", "sessions"): "radius:read",
    ("pki", "ca"): "pki:read", ("pki", "issued"): "pki:read", ("pki", "acme"): "pki:read",
    ("pki", "enrolments"): "pki:read",
    ("ssh",): "session",                # SSH certificates: anyone may look; signing is for fabric admins (2.1.7.12)
    ("ssh", "hosts"): "domain:read",    # each machine's SSH host certificate (1.6.11.9.11): the site's machines
    ("devices",): "devices:read",
    ("people",): "people:read",
    ("domain",): "domain:read", ("domain", "logon"): "domain:read", ("gpo",): "domain:read",
    ("host-groups",): "domain:read", ("sudo",): "domain:read",
    ("federation",): "federation:read",
    ("vault",): "vault:status", ("vault", "slots"): "vault:status", ("vault", "devices"): "vault:status",
    ("security",): "security:raise",
}
POST = {
    ("events",): "session", ("jobs", "doctor"): "status:read", ("jobs", "images"): "images:update",
    ("security", "raise"): "security:raise", ("security", "kerberos"): "security:raise",
    ("zones",): "dns:write", ("zones", "*", "delete"): "dns:write",
    ("zones", "*", "records"): "dns:write", ("zones", "*", "records", "delete"): "dns:write",
    ("zones", "*", "records", "link"): "dns:write",
    ("apply",): "dns:write",
    ("dns-filter", "querylog"): "dns:querylog",        # who looked up what: the admin bundle only (2.1.12.4)
    ("dns-filter", "lists"): "dns:filter", ("dns-filter", "lists", "set"): "dns:filter",
    ("dns-filter", "lists", "delete"): "dns:filter",
    ("dns-filter", "rules"): "dns:filter", ("dns-filter", "rules", "delete"): "dns:filter",
    ("dns-filter", "upstreams"): "dns:filter", ("dns-filter", "fetch"): "dns:filter",
    ("dns-filter", "groups"): "dns:filter", ("dns-filter", "groups", "delete"): "dns:filter",
    ("dns-filter", "safe-search"): "dns:filter",
    ("pki", "describe-csr"): "pki:read", ("pki", "inspect"): "pki:read",
    ("pki", "sign"): "pki:sign", ("pki", "revoke"): "pki:revoke",
    ("pki", "issue"): "pki:issue", ("pki", "convert"): "pki:issue",
    ("pki", "enrol", "apple"): "pki:enrol", ("pki", "enrol", "p12"): "pki:enrol",
    ("pki", "enrolments", "*", "withdraw"): "pki:enrol",
    ("ssh", "sign"): "session",         # refused inside unless the person is a fabric admin (2.1.7.12)
    ("ssh", "on"): "system:admin", ("ssh", "off"): "system:admin",
    ("tsig",): "tsig:manage", ("tsig", "*", "rotate"): "tsig:manage", ("tsig", "*", "delete"): "tsig:manage",
    ("vault", "rotate"): "vault:unlock", ("vault", "slots", "add-usb"): "vault:unlock",
    ("vault", "slots", "add-security-key"): "vault:unlock", ("vault", "slots", "add-hsm"): "vault:unlock",
    ("vault", "slots", "*", "test"): "vault:unlock", ("vault", "slots", "*", "remove"): "vault:unlock",
    ("devices",): "devices:enroll", ("devices", "*"): "devices:admin", ("devices", "*", "delete"): "devices:admin",
    ("devices", "*", "certs"): "pki:link-device",
    ("roles",): "roles:admin", ("roles", "*"): "roles:admin", ("roles", "*", "delete"): "roles:admin",
    ("people",): "people:create", ("people", "*", "reset"): "people:reset",
    ("people", "*", "disable"): "people:disable", ("people", "*", "enable"): "people:disable",
    ("people", "*", "delete"): "people:remove", ("people", "*", "groups"): "people:groups",
    ("machines",): "machines:admin", ("machines", "*", "enable"): "machines:admin",
    ("machines", "*", "disable"): "machines:admin", ("machines", "*", "delete"): "machines:admin",
    ("domain", "password-policy"): "domain:admin",
    ("gpo", "search"): "domain:read", ("gpo", "set"): "gpo:admin", ("gpo", "clear"): "gpo:admin",
    ("domain", "logon", "set"): "gpo:admin", ("domain", "logon", "clear"): "gpo:admin",
    ("host-groups",): "machines:admin", ("host-groups", "*", "delete"): "machines:admin",
    ("host-groups", "*", "members"): "machines:admin",
    ("sudo",): "sudo:admin", ("sudo", "*", "delete"): "sudo:admin",
    ("dhcp", "on"): "dhcp:write", ("dhcp", "off"): "dhcp:write",
    ("dhcp", "reservations"): "dhcp:write", ("dhcp", "reservations", "*", "delete"): "dhcp:write",
    ("dhcp", "subnets"): "dhcp:write", ("dhcp", "subnets", "update"): "dhcp:write",
    ("dhcp", "subnets", "delete"): "dhcp:write", ("dhcp", "options"): "dhcp:write",
    ("dhcp", "options", "delete"): "dhcp:write", ("dhcp", "classes"): "dhcp:write",
    ("dhcp", "classes", "*", "delete"): "dhcp:write",
    # the Networks tab (manual 1.10.4.21): the site's plan; the site is checked again by ipam/common/site_scope
    ("networks", "*", "block"): "dhcp:write", ("networks", "*", "vlans"): "dhcp:write",
    ("networks", "*", "vlans", "*"): "dhcp:write", ("networks", "*", "vlans", "*", "delete"): "dhcp:write",
    ("networks", "*", "subnets"): "dhcp:write", ("networks", "*", "subnets", "*"): "dhcp:write",
    ("networks", "*", "subnets", "*", "delete"): "dhcp:write", ("networks", "*", "ranges"): "dhcp:write",
    ("networks", "*", "ranges", "delete"): "dhcp:write", ("networks", "*", "addresses"): "dhcp:write",
    ("networks", "*", "addresses", "*"): "dhcp:write", ("networks", "*", "addresses", "*", "delete"): "dhcp:write",
    # a scan sends packets onto the site's networks and offers to record what it finds: whoever may change DHCP
    ("ipam", "scan"): "dhcp:write", ("ipam", "scan", "record"): "dhcp:write",
    # the scan policy (2.1.10.28): a site's level with dhcp:write, the organisation's as its DHCP options are set
    ("ipam", "scan-policy"): "dhcp:write", ("ipam", "scan-policy", "org"): "dhcp:org-options",
    # Sync now (2.1.10.29): the plan poll at once and BIND's records, never an apply
    ("ipam", "sync"): "dhcp:write",
    # the address manager's DHCP options (2.1.10.23): a site's with dhcp:write, the organisation's with dhcp:org-options
    ("ipam", "options"): "dhcp:write", ("ipam", "classes"): "dhcp:write", ("ipam", "option-defs"): "dhcp:write",
    ("ipam", "netboot"): "dhcp:write",
    ("ipam", "options", "org"): "dhcp:org-options", ("ipam", "classes", "org"): "dhcp:org-options",
    ("ipam", "option-defs", "org"): "dhcp:org-options", ("ipam", "option-editors"): "dhcp:org-options",
    ("radius", "clients"): "radius:admin", ("radius", "clients", "*", "rotate"): "radius:admin",
    ("radius", "clients", "*", "delete"): "radius:admin", ("radius", "clients", "*", "set"): "radius:admin",
    # cutting a device off is its own permission (2.1.11.8)
    ("radius", "sessions", "disconnect"): "radius:coa", ("radius", "sessions", "reauthenticate"): "radius:coa",
    ("radius", "people"): "radius:admin", ("radius", "people", "*", "delete"): "radius:admin",
}


def required_permission(method, route):
    """Purpose: The permission an agent request needs; routes not in the table are refused (default deny).
    Inputs:  method — "GET" or "POST" (anything else allows nothing); route — the path after /v1/ as a list
             or tuple of segments.
    Returns: a permission name (e.g. "dns:write"), "session" (any signed-in fabric user), or None (route
             not allowed).
    Fails:   never — an unknown route gives None.
    Feeds:   agent/handler.py Handler.authorize (None -> 403 "not allowed").
    Notes:   an exact entry wins; otherwise the first same-length pattern in table order where "*" matches
             any one segment.
    """
    table = GET if method == "GET" else POST if method == "POST" else {}
    route = tuple(route)
    if route in table:
        return table[route]
    for pattern, perm in table.items():
        if len(pattern) == len(route) and all(p == "*" or p == r for p, r in zip(pattern, route)):
            return perm
    return None
