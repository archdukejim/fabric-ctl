import os

from fabriclib.common.errors import ValidationError
from fabriclib.directory.ssh_user_sites import ssh_user_sites
from fabriclib.vault.ssh.constants import HOST_PUBLISHED, PUBLISHED
from fabriclib.vault.ssh.parse_ssh_key import parse_ssh_key


def _published(v, name):
    """Purpose: a published CA key and its fingerprint, as machines fetch it.
    Inputs:  v — settings: deploy_base_dir; name — the file in /certs/ (PUBLISHED or HOST_PUBLISHED).
    Returns: (key line, fingerprint); ("", "") when it is not published or does not parse.
    Fails:   OSError reading it.
    Feeds:   ssh_overview."""
    path = os.path.join(v["deploy_base_dir"], "nginx", "www", "certs", name)
    if not os.path.exists(path):
        return "", ""
    with open(path) as f:
        key = f.read().strip()
    try:
        return key, parse_ssh_key(key)["fingerprint"]
    except ValidationError:
        return "", ""


def ssh_overview(v, user, sites_check=ssh_user_sites):
    """Purpose: the web console's SSH page (manual 1.6.11.9.5, 1.6.11.9.14): whether SSH certificates are on, the CA's
             public key and fingerprint as machines see it, and whether this person may get one and which sites it
             would name.
    Inputs:  v — settings: ssh_certificates, deploy_base_dir; user — the signed-in person (None for a root peer);
             sites_check — the sites' SSH users groups check (tests pass their own).
    Returns: {"on": bool, "public_key" (the published one, "" when off), "fingerprint", "host_public_key",
             "host_fingerprint" (the host CA's, published for clients: 1.6.11.9.11; "" when off), "may_sign": bool,
             "sites": [the sites the certificate would name], "why_not" (str: why may_sign is False, "" otherwise),
             "hours": 8}.
    Fails:   OSError reading the published key; a published key parse_ssh_key refuses shows as no key, never raises.
    Feeds:   agent route GET /v1/ssh."""
    on = bool(v.get("ssh_certificates"))
    key, fingerprint = _published(v, PUBLISHED) if on else ("", "")
    host_key, host_fingerprint = _published(v, HOST_PUBLISHED) if on else ("", "")
    may, why, sites = False, "", []
    if not on:
        why = "SSH certificates are off"
    elif not user:
        why = "no signed-in person"
    else:
        try:
            sites = sorted(set(sites_check(v, user)))
            may = bool(sites)
            why = "" if may else "you are not in any site's SSH users group (<site>-ssh-users)"
        except ValidationError as exc:
            why = f"the directory could not be asked: {exc}"
    return {"on": on, "public_key": key, "fingerprint": fingerprint, "host_public_key": host_key,
            "host_fingerprint": host_fingerprint, "may_sign": may, "sites": sites, "why_not": why, "hours": 8}
