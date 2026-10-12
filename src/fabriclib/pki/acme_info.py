def acme_info(v):
    """Purpose: what a LAN machine's ACME client needs (2.1.5.8, manual 1.5.1.4).
    Inputs:  v — settings: hostname_stepca (also where the CA's files are, 1.5.1.6), domain, host_ip, bind_dns_port,
             cert_service_days.
    Returns: list of str lines: the directory, trusting the root, the names and lifetime, http-01, dns-01.
    Fails:   KeyError for a missing hostname.
    Feeds:   pki/run_acme_command (`fabricctl acme info`), agent route GET /v1/pki/acme (the Step-CA tab's ACME)."""
    return [f"ACME directory: https://{v['hostname_stepca']}/acme/acme/directory",
            f"trust fabric's root CA first: http://{v['hostname_stepca']}/certs/ (check its fingerprint there)",
            f"names: <name>.{v['domain']} only; certificates live {int(v.get('cert_service_days', 47))} days: let "
            "the client renew at 30 days old",
            "http-01: the machine answers on port 80 for its name (nothing to enroll)",
            f"dns-01: sudo fabricctl acme enroll <name> --dns; the client sends RFC2136 updates to "
            f"{v.get('host_ip', '<host>')} port {v.get('bind_dns_port', 53)} with the key in /opt/acme-<name>/"
            "rfc2136.ini (copy it to the machine; it is a secret)"]
