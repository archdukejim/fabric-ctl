import datetime

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.ssh_user_sites import ssh_user_sites
from fabriclib.vault.common.approle_login import approle_login
from fabriclib.vault.common.bao_request import bao_request
from fabriclib.vault.constants import SETUP_CREDS
from fabriclib.vault.ssh.constants import MOUNT, ROLE, TTL
from fabriclib.vault.ssh.parse_ssh_key import parse_ssh_key
from fabriclib.vault.ssh.signable_sites import signable_sites

REFUSED_USERS = ("root",)       # never a principal: a certificate gets a person in as themselves only


def sign_ssh_key(v, actor, public_key, source="web", sites_check=ssh_user_sites, login=approle_login, now=None,
                 scope=signable_sites):
    """Purpose: an 8-hour SSH user certificate for a person in one or more sites' SSH users groups (manual
             1.6.11.9.3, 1.6.11.9.14; decisions 2.1.7.12, 2.1.7.14): only while SSH certificates are on; its
             principals `<user>@<site>`, one per site whose `<site>-ssh-users` the person is in, nested too, among
             this site and the sites below it (signable_sites: revised 2026-10-13, central IT at the top signs for
             every site, a branch only for its own).
    Inputs:  v — settings: ssh_certificates, and what bao_request and run_op need; actor — the signed-in person (never
             a name from the request); public_key — one OpenSSH public key line; source — the audit's; sites_check,
             login, scope — the membership check, the OpenBao login and the sites this CA signs for (tests pass
             their own); now — aware datetime.
    Returns: {"certificate" (the -cert.pub line), "serial", "principal" (the principals, comma-separated),
             "principals" (list), "sites" (list), "valid_hours": 8, "key_id", "fingerprint", "type"}.
    Fails:   ValidationError: SSH certificates off; a root peer without a person, or a user named root; a person in
             no site's SSH users group, or only in those of sites this site does not sign for (sites above or
             beside it: audited SSH_SIGN_REFUSED, naming them); parse_ssh_key's refusals; the directory
             unreachable; OpenBao refusing.
    Feeds:   agent route POST /v1/ssh/sign <- the web console's SSH page."""
    if not v.get("ssh_certificates"):
        raise ValidationError("SSH certificates are off on this site: a console admin turns them on (SSH page)")
    if not actor or actor == "root":
        raise ValidationError("an SSH certificate is for a person: sign in to the web console as yourself")
    key = parse_ssh_key(public_key)
    if actor.lower() in REFUSED_USERS:
        write_audit(actor, "SSH_SIGN_REFUSED", f"a reserved user name; key {key['type']} {key['fingerprint']}", source)
        raise ValidationError(f"no SSH certificate is signed for the user name {actor}")
    sites = sorted(set(sites_check(v, actor)))
    if not sites:
        write_audit(actor, "SSH_SIGN_REFUSED", f"not in any site's SSH users group; key {key['type']} "
                                               f"{key['fingerprint']}", source)
        raise ValidationError("you are not in any site's SSH users group (<site>-ssh-users), so no SSH certificate "
                              f"is signed: ask the admin of the site you need (here: {v.get('site_name', '<site>')}"
                              "-ssh-users)")
    sites, elsewhere = scope(v, sites)
    if not sites:
        write_audit(actor, "SSH_SIGN_REFUSED", f"SSH users only of sites this site does not sign for "
                                               f"({', '.join(elsewhere)}); key {key['type']} {key['fingerprint']}",
                    source)
        raise ValidationError(f"this site ({v.get('site_name', '?')}) signs SSH certificates only for itself and the "
                              f"sites below it; you are in the SSH users group of {', '.join(elsewhere)}: get your "
                              "certificate at that site, or at a site above it")
    principals = [f"{actor}@{s}" for s in sites]
    now = now or datetime.datetime.now(datetime.timezone.utc)
    key_id = f"fabric:{actor}:{now.strftime('%Y%m%dT%H%M%SZ')}"
    status, data = bao_request(v, "POST", f"{MOUNT}/sign/{ROLE}", token=login(v, SETUP_CREDS), body={
        "public_key": key["line"], "valid_principals": ",".join(principals), "cert_type": "user", "ttl": TTL,
        "key_id": key_id})
    if status != 200:
        raise ValidationError(f"OpenBao did not sign the key: {data.get('errors') or status}")
    signed = (data.get("data") or {})
    write_audit(actor, "SSH_SIGN", f"principals={','.join(principals)} key={key['type']} {key['fingerprint']} "
                                   f"serial={signed.get('serial_number', '?')} valid={TTL}", source)
    return {"certificate": signed.get("signed_key", "").strip(), "serial": signed.get("serial_number", ""),
            "principal": ",".join(principals), "principals": principals, "sites": sites, "valid_hours": 8,
            "key_id": key_id, "fingerprint": key["fingerprint"], "type": key["type"]}
