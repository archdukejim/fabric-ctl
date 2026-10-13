from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def is_fabric_admin(v, user):
    """Purpose: ask the domain whether a person is a fabric admin: a member, nested too, of `fabric-admins` or the
             site's `<site>-fabric-admins` (manual 1.6.11.2; who may get an SSH certificate, 2.1.7.12).
    Inputs:  v — settings (run_op's: site_name); user — the user name.
    Returns: bool.
    Fails:   ValidationError from run_op (the directory unreachable; "no such user: …"); from load_secrets (OpenBao
             locked).
    Feeds:   vault/ssh/sign_ssh_key, vault/ssh/ssh_overview."""
    return bool(run_op(v, load_secrets(), "is_fabric_admin", {"uid": user}).get("fabric_admin"))
