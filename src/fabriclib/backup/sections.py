"""The seven sections of a backup bundle (manual 1.3.7.3, decision 2.1.3.6): what each holds, which vars.yaml keys it
owns, and what depends on it. Constants only; section_paths and section_of_key read them."""

ORDER = ("settings", "pki", "secrets", "directory", "dns", "signin", "dhcp")

SECTIONS = {
    "settings": {
        "what": "vars.yaml (all of it), fabric's config, the audit log, federation's registry, the run records",
        "dirs": ["fabric", "nginx", "webui", "federation", "freeradius", "fluentbit", "dirsrv"],
        "outside": [],
        "keys": [],                      # every key no other section owns
        "depends": [],
    },
    "pki": {
        "what": "Step-CA whole (root and intermediate keys, its database) and every issued certificate and key",
        "dirs": ["stepca", "nginx/certs", "bind9/ssl", "keycloak/certs", "postgres/certs", "openbao/certs",
                 "webui/certs"],
        "outside": [],
        "keys": ["ca_", "byoc", "ica_", "cert_", "pki_manual_", "stepca_cert_", "site_ca_depth"],
        "depends": [],
    },
    "secrets": {
        "what": "OpenBao's data, its vault key and unlock-method files",
        "dirs": ["openbao"],
        "outside": ["openbao_key_dir"],
        "keys": ["openbao_"],
        "depends": ["settings", "pki", "directory", "dns", "signin", "dhcp"],
        "alone": False,                  # 2.1.1.106 point 2: only in a whole restore
    },
    "directory": {
        "what": "the domain: Samba's database and SYSVOL (people, groups, machines, devices, policies, the address "
                "plan)",
        "dirs": ["samba"],
        "outside": [],
        "keys": ["ad_", "dc_name", "ldap_", "posix_"],
        "depends": ["dns", "dhcp"],
    },
    "dns": {
        "what": "BIND's zones and keys, the resolver, the DNS filter and AdGuard Home's settings",
        "dirs": ["bind9", "resolver", "dnsfilter", "adguard", "adguard-auth"],
        "outside": [],
        "keys": ["dns", "dns_fabric_own", "dns_filter", "tsig_keys", "bind_acl"],
        "depends": ["directory"],
    },
    "signin": {
        "what": "Keycloak and its Postgres database (second factors, sessions)",
        "dirs": ["keycloak", "postgres"],
        "outside": ["keycloak_data_dir", "postgres_data_dir"],
        "keys": ["signin_"],
        "depends": [],
    },
    "dhcp": {
        "what": "Kea's files and leases",
        "dirs": ["kea"],
        "outside": [],
        "keys": ["dhcp"],
        "depends": [],
    },
}

# keys that look like a section's prefix but are the host's sizing or wiring, so stay in settings
SETTINGS_KEYS = {"openbao_mem_limit", "dns_server", "postgres_data_dir", "keycloak_data_dir"}
