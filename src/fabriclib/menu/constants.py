"""What the vars editor (`fabricctl --interactive`) treats specially."""

# fixed once installed: never edited or deleted from the menu (ad_domain: 2.1.6.11; dc_name: an AD DC cannot be
# renamed, 2.1.6.45, and fabric names it, 2.1.6.65; friendly_name: the CA's name is made from it). Setup marks its
# questions for these "⚠ Permanent" (setup/permanent_mark, 2.1.2.20): one list for both.
IMMUTABLE_KEYS = {
    "ad_domain", "ca_name", "cert_country", "cert_province", "cert_city", "cert_org", "cert_ou",
    "cert_root_digest", "cert_root_key_type", "cert_root_key_param", "cert_root_ca_days",
    "cert_intermediate_days", "cert_intermediate_digest", "cert_intermediate_key_type",
    "cert_intermediate_key_param", "cert_service_days", "cert_acme_lifetime_hours",
    "stepca_port", "stepca_cert_allow_subordinate_ca", "stepca_cert_max_lifetime_hours",
    "byoc", "ca_crt_path", "ica_crt_path", "ica_key_path", "extra_certs",
    "deploy_base_dir", "domain", "org_domain", "site_name", "dc_name", "friendly_name",
    "posix_id_start", "posix_id_block",     # the uid/gid blocks' start and size (2.1.6.46)
}

# changing these can cut the host off its network, or rename it (hostname: its certificates and pages, never the DC,
# 2.1.6.45): the menu asks before applying
WARNED_KEYS = {"host_ip", "lan_cidr", "lan_gateway", "fabric_subnet", "hostname"}

# the "Docker & Services" screen
SERVICE_KEYS = [
    "host_ram_capacity", "compose_file", "project_containers", "nginx_backend_stepca",
    "keycloak_data_dir", "postgres_data_dir", "ip_nginx", "ip_bind9", "ip_stepca", "ip_keycloak",
    "ip_postgres", "image_nginx", "image_debian", "image_stepca", "image_keycloak", "image_postgres",
    "cname_ca", "landing_page_cname", "cname_dns", "cname_sso", "cname_mgr", "hostname_nginx",
    "hostname_bind9", "hostname_stepca", "hostname_landing", "hostname_keycloak", "hostname_mgr",
]

# fields asked for by the list editors
LIST_SCHEMAS = {
    "tsig_keys": ["name", "algorithm", "domain", "record_types", "records"],
    "ldap_groups": ["gidNumber", "name", "permissions"],
    "ldap_organizational_units": ["name", "description", "parent"],
}
