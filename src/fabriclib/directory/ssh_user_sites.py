from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def ssh_user_sites(v, user):
    """Purpose: ask the domain which sites' remote users groups a person is in, nested too, and for which machine
             class (decision 2.1.7.14 as revised 2026-10-13, manual 1.6.11.9.14): what their SSH certificate names.
    Inputs:  v — settings (run_op's: site_name); user — the user name.
    Returns: list of {"site", "class" ("server" | "desktop")}, sorted (empty: none).
    Fails:   ValidationError from run_op (the directory unreachable; "no such user: …"); from load_secrets (OpenBao
             locked).
    Feeds:   vault/ssh/sign_ssh_key, vault/ssh/ssh_overview."""
    return list(run_op(v, load_secrets(), "ssh_user_sites", {"uid": user}).get("grants") or [])
