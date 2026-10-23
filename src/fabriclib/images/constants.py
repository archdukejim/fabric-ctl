"""The services whose images fabric manages, in update order (dependencies
first). `var` is the vars key holding the pinned ref (for local builds: the
base they are built FROM); `build` is the local image name, if any;
`published` names fabric's published image that replaces the local build
where the host can use it (manual 1.14.3, images/effective_service)."""
SERVICES = [
    {"name": "bind9", "unit": "bind9", "container": "bind9", "folder": "bind9", "var": "image_debian",
     "build": "fabric/bind9:local",
     "published": "bind9"},
    # the DNS filter's resolver runs bind9's image (manual 1.12.2.4): moved with it, right after it
    {"name": "resolver", "unit": "bind9-resolver", "container": "bind9-resolver", "folder": "resolver",
     "var": "image_debian", "build": "fabric/bind9:local",
     "published": "bind9"},
    {"name": "stepca", "unit": "stepca", "container": "step-ca", "folder": "stepca", "var": "image_stepca",
     "build": "fabric/stepca:local",
     "published": "stepca"},
    {"name": "postgres", "unit": "postgres", "container": "postgres", "folder": "postgres", "var": "image_postgres",
     "build": None},
    {"name": "keycloak", "unit": "keycloak", "container": "keycloak", "folder": "keycloak", "var": "image_keycloak",
     "build": "fabric/keycloak:local",
     "published": "keycloak"},
    {"name": "openbao", "unit": "openbao", "container": "openbao", "folder": "openbao", "var": "image_openbao",
     "build": None},
    {"name": "nginx", "unit": "nginx", "container": "nginx", "folder": "nginx", "var": "image_nginx", "build": None},
    {"name": "kea", "unit": "kea", "container": "kea-dhcp4", "folder": "kea", "var": "image_debian",
     "build": "fabric/kea:local",
     "published": "kea"},
    {"name": "freeradius", "unit": "freeradius", "container": "freeradius", "folder": "freeradius",
     "var": "image_debian", "build": "fabric/freeradius:local",
     "published": "freeradius"},
    {"name": "samba", "unit": "samba", "container": "samba", "folder": "samba", "var": "image_debian",
     "build": "fabric/samba:local",
     "published": "samba"},
    # the DNS filter's list matcher (manual 1.12.3): AdGuard Home's own image, behind the resolver
    {"name": "adguard", "unit": "adguard-filter", "container": "adguard-filter", "folder": "dnsfilter",
     "var": "image_adguard", "build": None},
    {"name": "fluentbit", "unit": "fluentbit", "container": "fluentbit", "folder": "fluentbit",
     "var": "image_fluentbit",
     "build": None},
    {"name": "fabric-web", "unit": "fabric-web", "container": "fabric-web", "folder": "webui", "var": "image_debian",
     "build": "fabric/web:local",
     "published": "webui"},
]
# services whose unit Requires= another's (deploy/service_units.py): an image switch restarts them, health-gated,
# after it (2.3.1.21.1)
DEPENDENTS = {"postgres": ["keycloak"]}
STATE = "/etc/fabric/images/state.json"      # previous ref per image var (for rollback), root 0600
VERIFIED = "/etc/fabric/images/verified.json"  # digests whose signature verified (manual 1.14.3.4), root 0600
# the last offline bundle imported, when it left images out (2.1.14.21), root 0600
BUNDLE_RECORD = "/etc/fabric/images/bundle.json"
