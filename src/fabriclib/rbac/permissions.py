"""Who may do what in fabric (design 2.1.6.1). Each permission is a Keycloak
realm role named PREFIX + name ("fabric:dns:write"); each bundle is a
composite realm role of permissions, granted to directory groups. The
fabric-agent checks every request against these (required_permission.py);
the web UI only hides what the user cannot do."""
PREFIX = "fabric:"

PERMISSIONS = {
    "status:read": "see the services' health (Overview)",
    "dns:read": "see zones, records, reverse zones and TSIG key names",
    "dns:write": "add and remove DNS records, apply DNS changes",
    "tsig:manage": "create, rotate and delete TSIG keys",
    "dns:filter": "manage the DNS filter (lists, rules, client groups) and see its statistics",
    "dns:querylog": "read the DNS query log: which client looked up which name (admin bundle only, 2.1.12.4)",
    "dhcp:read": "see DHCP subnets, reservations and leases",
    "dhcp:write": "add and remove DHCP reservations",
    "pki:read": "see the CA and issued certificates; inspect a CSR or certificate",
    "pki:issue": "issue key + certificate pairs, convert to .p12",
    "pki:sign": "sign uploaded CSRs",
    "pki:revoke": "revoke issued certificates (published in the CRL at once, 2.1.5.10)",
    "pki:link-device": "link a certificate to a device",
    "devices:read": "see devices and device roles",
    "devices:enroll": "add devices",
    "devices:admin": "change, disable and delete devices",
    "roles:admin": "create, change and delete device roles",
    "radius:read": "see 802.1X (FreeRADIUS) state",
    "radius:admin": "change 802.1X settings",
    "people:read": "see realm users",
    "people:create": "create realm users",
    "people:reset": "reset a user's sign-in (password, TOTP)",
    "people:disable": "disable a user's sign-in everywhere at once, or enable it again",
    "people:remove": "remove a user and revoke their certificates",
    "people:groups": "change which groups a user is in",
    "domain:read": "see the domain: its controller, password policy, machines and Group Policy settings",
    "domain:admin": "change the domain's password policy (2.1.2.22; admins only)",
    "machines:admin": "pre-create, disable, enable and remove the site's machines; its host groups and their machines",
    "sudo:admin": "add and remove the site's sudo rules on its Linux machines (admin bundle, 1.6.11.7)",
    "gpo:admin": "set and clear policies in the site's admin settings GPO, and who may sign in to its machines",
    "federation:read": "see the federation: sites, DC replication and conflicts, limits, the address plan",
    "vault:status": "see OpenBao's state and unlock methods",
    "vault:unlock": "add, test, remove unlock methods; rotate the vault key",
    "audit:read": "read the audit log",
    "system:admin": "services, updates and settings",
    "images:update": "update a service's container image, or roll it back (2.1.8.3)",
    "security:raise": "raise sign-in security: second factors, the web console's client certificate (2.1.6.27)",
}

_READ = ["status:read", "dns:read", "dhcp:read", "pki:read", "devices:read", "radius:read", "people:read",
         "domain:read", "federation:read", "vault:status",
         "audit:read"]

# the web console's admin role (webui_admin_role): fabric-admin until 0.6.4, now the first admin's user name (2.1.6.33)
ADMIN_ROLE = "fabric-console-admin"
OLD_ADMIN_ROLE = "fabric-admin"

# bundle -> permissions. "admin" is the web UI admin role (webui_admin_role, default ADMIN_ROLE).
BUNDLES = {
    "admin": sorted(PERMISSIONS),
    "fabric-auditor": _READ,
    "fabric-network-operator": ["status:read", "dns:read", "dns:write", "tsig:manage", "dns:filter", "dhcp:read",
                                "dhcp:write",
                                "pki:read", "vault:status"],
    "fabric-equipment-operator": ["status:read", "dns:read", "pki:read", "pki:link-device", "devices:read",
                                  "devices:enroll", "devices:admin", "roles:admin", "radius:read", "radius:admin",
                                  "domain:read", "machines:admin"],
    "fabric-pki-operator": ["status:read", "pki:read", "pki:issue", "pki:sign", "pki:revoke", "pki:link-device",
                           "devices:read"],
    "fabric-helpdesk": ["status:read", "dns:read", "pki:read", "devices:read", "devices:enroll", "people:read",
                        "people:create", "people:reset", "people:disable", "domain:read"],
}
