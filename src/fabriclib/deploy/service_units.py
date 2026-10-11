def service_units(base, v):
    """Purpose: fabric's container services, each run by a systemd wrapper unit around its compose file.
    Inputs:  base — the deploy base (/opt); v — rendered settings (install_* flags).
    Returns: [{"service" (unit), "compose" (the container its health check waits on), "folder" (<base>/<folder>,
             jinja/<folder>), "requires" (units), optional "condition", "post", "enabled" (bool: installed on this
             host)}], in a fixed order.
    Fails:   never.
    Feeds:   render_templates (compose files and wrappers of the enabled ones), install_service_units;
             tests/render.py (every unit's container must be in its compose file)."""
    cli = f"/usr/bin/python3 {base}/fabric/lib/fabriclib/cli.py"
    units = [
        {'service': 'nginx', 'compose': 'nginx', 'folder': 'nginx', 'requires': []},
        {'service': 'bind9', 'compose': 'bind9', 'folder': 'bind9', 'requires': []},
        {'service': 'stepca', 'compose': 'step-ca', 'folder': 'stepca', 'requires': []},
        {'service': 'postgres', 'compose': 'postgres', 'folder': 'postgres', 'requires': []},
        {'service': 'keycloak', 'compose': 'keycloak', 'folder': 'keycloak', 'requires': ['postgres']},
        {'service': 'fabric-web', 'compose': 'fabric-web', 'folder': 'webui', 'requires': ['fabric-agent']},
        # fabric-unlock: OpenBao starts only when an unlock method gives its key; the key is wiped once unsealed.
        {'service': 'openbao', 'compose': 'openbao', 'folder': 'openbao', 'requires': [],
         'condition': f"{cli} vault unlock", 'post': [f"{cli} vault wipe-key"]},
        # optional log forwarding (design 2.1.15.1)
        {'service': 'fluentbit', 'compose': 'fluentbit', 'folder': 'fluentbit', 'requires': []},
        # optional DHCP (design §5): kea-dhcp4 on the host network + kea-ddns
        {'service': 'kea', 'compose': 'kea-dhcp4', 'folder': 'kea', 'requires': ['bind9']},
        # optional 802.1X (design §6): asks the domain controller about every device
        {'service': 'freeradius', 'compose': 'freeradius', 'folder': 'freeradius', 'requires': []},
        # the directory (manual 1.6.5): the Samba AD DC on the host network, on every install; no requires: BIND
        # reads its database for the AD zone, but a DC restart must not take DNS down, nor a BIND restart the DC
        {'service': 'samba', 'compose': 'samba', 'folder': 'samba', 'requires': []},
        # the DNS filter, a BIND resolver (manual 1.12.2): on host_ip:53; no requires: an apply that restarts the
        # authoritative BIND (every DNS apply) must not take the clients' DNS down with it
        {'service': 'bind9-resolver', 'compose': 'bind9-resolver', 'folder': 'resolver', 'requires': []},
        # its list matcher, AdGuard Home behind it (manual 1.12.3): no requires either way, so a restart of one never
        # takes the other down (while AdGuard restarts, the resolver answers internet names SERVFAIL: fail closed)
        {'service': 'adguard-filter', 'compose': 'adguard-filter', 'folder': 'dnsfilter', 'requires': []},
    ]
    flag = {"keycloak": "install_keycloak", "postgres": "install_keycloak",
            "webui": "install_webui", "fluentbit": "install_fluentbit", "kea": "install_kea",
            "freeradius": "install_freeradius", "resolver": "install_resolver", "dnsfilter": "install_resolver"}
    for u in units:
        u["enabled"] = bool(v.get(flag[u["folder"]])) if u["folder"] in flag else True
    return units
