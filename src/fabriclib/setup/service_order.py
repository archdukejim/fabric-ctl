"""fabric's container services in dependency order: setup starts them in it (start_services) and an apply's rollout
restarts them in it (deploy/restart_changed, 2.1.14.15)."""

# (systemd unit, container, enabled-if flag); order = start order
ORDER = [("bind9", "bind9", None), ("stepca", "step-ca", None), ("samba", "samba", None),
         ("postgres", "postgres", "install_keycloak"), ("keycloak", "keycloak", "install_keycloak"),
         ("nginx", "nginx", None), ("fluentbit", "fluentbit", "install_fluentbit"),
         ("kea", "kea-dhcp4", "install_kea"), ("freeradius", "freeradius", "install_freeradius"),
         ("adguard-filter", "adguard-filter", "install_resolver"),
         ("bind9-resolver", "bind9-resolver", "install_resolver")]
