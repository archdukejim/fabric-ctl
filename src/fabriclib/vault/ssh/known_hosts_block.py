BEGIN = "# fabric: SSH host CA, begin (manual 1.6.11.9.9; written by fabric, kept in step with SSH certificates)"
END = "# fabric: SSH host CA, end"


def known_hosts_block(ca_key, domains):
    """Purpose: the lines an SSH client's known-hosts file needs to trust fabric's host CA (manual 1.6.11.9.9): for
             every name in the site's domains, and for short names (no dot, no colon: a bare name the resolver's
             search domain completes), never for any other name, so the CA can never vouch for a host outside the
             domain.
    Inputs:  ca_key — the host CA's public key line ("ssh-ed25519 AAAA…"); domains — the DNS domains (ad_domain,
             domain; empty and repeated ones dropped).
    Returns: str: BEGIN, the @cert-authority lines (the domains' names, then short names), END, each ending in a
             newline.
    Fails:   never.
    Feeds:   vault/ssh/apply_host_ssh_cert (the fabric host); the same lines are written by the join script's
             fabric-managed on each managed machine (templates/nginx/www/certs/join-linux.sh.j2)."""
    key = " ".join(str(ca_key).split()[:2])
    names = []
    for d in domains:
        d = str(d or "").strip().strip(".").lower()
        if d and f"*.{d}" not in names:
            names.append(f"*.{d}")
    domain_line = f"@cert-authority {','.join(names)} {key}\n" if names else ""
    return f"{BEGIN}\n{domain_line}@cert-authority *,!*.*,!*:* {key}\n{END}\n"
