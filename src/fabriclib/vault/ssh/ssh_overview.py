import os

from fabriclib.common.errors import ValidationError
from fabriclib.directory.is_fabric_admin import is_fabric_admin
from fabriclib.vault.ssh.constants import PUBLISHED
from fabriclib.vault.ssh.parse_ssh_key import parse_ssh_key


def ssh_overview(v, user, admin_check=is_fabric_admin):
    """Purpose: the web console's SSH page (manual 1.6.11.9.5): whether SSH certificates are on, the CA's public key
             and fingerprint as machines see it, and whether this person may get one.
    Inputs:  v — settings: ssh_certificates, deploy_base_dir; user — the signed-in person (None for a root peer);
             admin_check — the fabric-admins check (tests pass their own).
    Returns: {"on": bool, "public_key" (the published one, "" when off), "fingerprint", "may_sign": bool,
             "why_not" (str: why may_sign is False, "" otherwise), "hours": 8}.
    Fails:   OSError reading the published key; a published key parse_ssh_key refuses shows as no key, never raises.
    Feeds:   agent route GET /v1/ssh."""
    on = bool(v.get("ssh_certificates"))
    path = os.path.join(v["deploy_base_dir"], "nginx", "www", "certs", PUBLISHED)
    key = ""
    if on and os.path.exists(path):
        with open(path) as f:
            key = f.read().strip()
    try:
        fingerprint = parse_ssh_key(key)["fingerprint"] if key else ""
    except ValidationError:
        key, fingerprint = "", ""
    may, why = False, ""
    if not on:
        why = "SSH certificates are off"
    elif not user:
        why = "no signed-in person"
    else:
        try:
            may = admin_check(v, user)
            why = "" if may else "only fabric admins get SSH certificates"
        except ValidationError as exc:
            why = f"the directory could not be asked: {exc}"
    return {"on": on, "public_key": key, "fingerprint": fingerprint, "may_sign": may, "why_not": why, "hours": 8}
