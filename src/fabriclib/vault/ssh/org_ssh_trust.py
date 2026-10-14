from fabriclib.common.errors import ValidationError
from fabriclib.vault.ssh.parse_ssh_key import parse_ssh_key


def _key(line):
    """Purpose: an SSH public key line reduced to "<type> <base64>", or "" when it does not parse.
    Inputs:  line — str.
    Returns: str.
    Fails:   never.
    Feeds:   org_ssh_trust."""
    try:
        return " ".join(parse_ssh_key(line)["line"].split()[:2])
    except (ValidationError, KeyError):
        return ""


def _patterns(domains):
    """Purpose: known-hosts name patterns for domains: `*.<domain>` each, lower case, once, in order.
    Inputs:  domains — iterable of str (empty ones dropped).
    Returns: list of str.
    Fails:   never.
    Feeds:   org_ssh_trust."""
    out = []
    for d in domains:
        d = str(d or "").strip().strip(".").lower()
        if d and f"*.{d}" not in out:
            out.append(f"*.{d}")
    return out


def org_ssh_trust(v, own_user_ca, own_host_ca, sites):
    """Purpose: what this site's machines trust from the organisation's SSH CAs (decision 2.1.7.14, manual
             1.6.11.9.16): every site's host CA, each for `*.<ad_domain>` and that site's own domain (this site's also
             for short names, which only it can complete), and as user CAs this site's own and those of the sites
             whose DC is writable (as AD's configuration says, read_ssh_cas).
    Inputs:  v — settings: site_name, ad_domain, domain; own_user_ca, own_host_ca — this site's CA key lines (from
             OpenBao; "" when none); sites — read_ssh_cas's list [{"site", "user_ca", "host_ca", "domain",
             "writable"}].
    Returns: {"user_cas": [key lines, this site's first], "known": [@cert-authority lines, this site's first]}; keys
             that do not parse are left out, each key once.
    Fails:   never.
    Feeds:   vault/ssh/sign_ssh_hosts (published as ssh-user-cas.pub and ssh-host-cas.known; the fabric host's own
             known-hosts block)."""
    me = v.get("site_name")
    user_cas, known, hosts_seen = [], [], set()
    own_user, own_host = _key(own_user_ca), _key(own_host_ca)
    if own_user:
        user_cas.append(own_user)
    if own_host:
        known.append(f"@cert-authority {','.join(_patterns([v.get('ad_domain'), v.get('domain')]))} {own_host}")
        known.append(f"@cert-authority *,!*.*,!*:* {own_host}")
        hosts_seen.add(own_host)
    for s in sorted(sites, key=lambda e: e.get("site", "")):
        if s.get("site") == me:
            continue
        host = _key(s.get("host_ca", ""))
        if host and host not in hosts_seen:
            pats = _patterns([v.get("ad_domain"), s.get("domain")])
            known.append(f"@cert-authority {','.join(pats)} {host}")
            hosts_seen.add(host)
        user = _key(s.get("user_ca", ""))
        if user and s.get("writable") and user not in user_cas:
            user_cas.append(user)
    return {"user_cas": user_cas, "known": known}
