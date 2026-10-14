from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def ssh_user_sites(v, user):
    """Purpose: ask the domain which sites' SSH users groups a person is in, nested too (decision 2.1.7.14, manual
             1.6.11.9.14): the sites their SSH certificate names.
    Inputs:  v — settings (run_op's: site_name); user — the user name.
    Returns: list of site names, sorted (empty: none).
    Fails:   ValidationError from run_op (the directory unreachable; "no such user: …"); from load_secrets (OpenBao
             locked).
    Feeds:   vault/ssh/sign_ssh_key, vault/ssh/ssh_overview."""
    return list(run_op(v, load_secrets(), "ssh_user_sites", {"uid": user}).get("sites") or [])
