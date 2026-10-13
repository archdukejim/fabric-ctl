import re

from fabriclib.common.errors import ValidationError

SHORT = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
# never certified, whatever a computer account is called: names every client resolves to itself
RESERVED = ("localhost", "localhost6", "ip6-localhost", "ip6-loopback")


def host_principals(account, domains):
    """Purpose: the names a machine's SSH host certificate names (manual 1.6.11.9.7; decision 2.1.7.13): its short
             name and its name in each of the site's domains, all from its computer account's sAMAccountName, which
             only an admin can change — never from dNSHostName or anything else the machine writes itself.
    Inputs:  account — the sAMAccountName ("WS2404$", any case; the trailing $ optional), or the fabric host's own
             hostname; domains — the DNS domains to name it in (ad_domain, domain; empty and repeated ones dropped).
    Returns: list of str, lower case: [short, short.<domain>, …], each once, in that order.
    Fails:   ValidationError when the name is not a host name (letters, digits, inner dashes) or is reserved
             (localhost and its kin).
    Feeds:   vault/ssh/sign_ssh_hosts."""
    short = str(account or "").strip().rstrip("$").lower()
    if not SHORT.match(short) or short in RESERVED:
        raise ValidationError(f"not a host name fabric certifies: {short[:64]!r}")
    out = [short]
    for domain in domains:
        domain = str(domain or "").strip().strip(".").lower()
        name = f"{short}.{domain}"
        if domain and name not in out:
            out.append(name)
    return out
