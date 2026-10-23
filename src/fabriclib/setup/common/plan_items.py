"""The plan's hardened defaults (manual 1.2.9.11.4): (settings key, default, what enabling it does, what relaxing it
costs). Shown by choose_plan; their effective values are recorded by apply_plan_defaults."""

PLAN = [
    ("security.firewall", True,
     "Host firewall: only fabric's ports inbound, from the LAN only (also enforced for Docker-published ports)",
     "every published port (DNS, LDAP, HTTPS, ...) reachable from any network that can route to this host"),
    ("security.docker_daemon_hardening", True,
     "Harden the Docker daemon (no-new-privileges, no inter-container traffic on the default bridge, "
     "no userland proxy, live-restore, bounded logs)",
     "containers may gain privileges via setuid binaries; logs can fill the disk"),
    ("host_join_domain", True,
     "Make this host a member of its domain: fabric admins sign in to it with their domain accounts (local accounts "
     "unchanged; [M]enu to change)",
     "fabric admins sign in to this host with local accounts only"),
    ("install_keycloak", True, "Keycloak SSO (+ Postgres), required by the web UI", "no SSO and no web UI"),
    ("install_webui", True, "Fabric web UI at https://fabric-ctl.<domain> (Keycloak sign-in)",
     "manage with fabricctl only"),
]
