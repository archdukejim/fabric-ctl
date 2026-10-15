"""Ordered setup steps. Each is idempotent and can run alone:
`fabricctl setup --step <name>`."""
from fabriclib.setup import (condition_host, configure_firewall, configure_network, create_accounts, create_admin,
                             deploy_config, ensure_db_rotation,
                             harden_docker, init_pki, join_federation, join_host_domain, mint_service_certs, preflight,
                             setup_openbao,
                             start_bootstrap, start_services, verify_install, wait_ready)

STEPS = [
    ("preflight", preflight.run, "check architecture, OS, RAM, cgroup memory controller, ports"),
    ("host", condition_host.run, "host packages and Docker Engine"),
    ("docker", harden_docker.run, "harden the Docker daemon"),
    ("join", join_federation.run, "join an upstream fabric (only with --join)"),
    ("deploy", deploy_config.run, "render and deploy configuration; install the fabricctl command"),
    ("accounts", create_accounts.run, "service users and groups"),
    ("network", configure_network.run, "docker network fabric_net; host resolver"),
    ("firewall", configure_firewall.run, "host firewall + LAN-only Docker-published ports"),
    ("pki", init_pki.run, "initialise Step-CA; publish and trust the CA"),
    ("bootstrap", start_bootstrap.run, "start bind9 and step-ca; check zones"),
    ("certs", mint_service_certs.run, "issue/renew service certificates"),
    ("start", start_services.run, "start everything; converge the domain; configure Keycloak; web UI"),
    ("member", join_host_domain.run,
     "this host as a member of its own domain: domain sign-in as its OU's policy allows (host_join_domain)"),
    ("vault", setup_openbao.run,
     "OpenBao: vault key + unlock methods, init once (recovery keys to ~/fabric-admin), configure, import secrets"),
    ("dbrotation", ensure_db_rotation.run,
     "Keycloak's database password: Postgres's own admin, OpenBao's database engine (rotated monthly)"),
    ("admin", create_admin.run, "first web UI admin: a person in the domain, client certificate, login kit"),
    ("verify", verify_install.run, "end-to-end checks (same as fabricctl doctor)"),
    ("ready", wait_ready.run, "wait until the landing page, sign-in and the console answer and Keycloak's database "
                              "has settled"),
]
