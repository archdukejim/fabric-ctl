BEGIN = "# fabric: SSH host CA, begin (manual 1.6.11.9.9; written by fabric, kept in step with SSH certificates)"
END = "# fabric: SSH host CA, end"


def known_hosts_block(ca_key, domains, revoked=()):
    """Purpose: the lines an SSH client's known-hosts file needs to trust fabric's host CA (manual 1.6.11.9.9): for
             every name in the site's domains, and for short names (no dot, no colon: a bare name the resolver's
             search domain completes), never for any other name, so the CA can never vouch for a host outside the
             domain; and an @revoked line for each host key whose certificate fabric withdrew before it ran out
             (1.6.11.9.12), so a client refuses that key at once, with its certificate or without.
    Inputs:  ca_key — the host CA's public key line ("ssh-ed25519 AAAA…"); domains — the DNS domains (ad_domain,
             domain; empty and repeated ones dropped); revoked — host public key lines ("<type> <base64>").
    Returns: str: BEGIN, the @cert-authority lines (the domains' names, then short names), the @revoked lines (sorted,
             each once), END, each ending in a newline.
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
    gone = sorted({" ".join(str(r).split()[:2]) for r in revoked if len(str(r).split()) >= 2})
    revoked_lines = "".join(f"@revoked * {r}\n" for r in gone)
    return f"{BEGIN}\n{domain_line}@cert-authority *,!*.*,!*:* {key}\n{revoked_lines}{END}\n"
