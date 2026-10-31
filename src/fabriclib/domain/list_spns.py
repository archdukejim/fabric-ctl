from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def list_spns(v, secrets=None, container="samba"):
    """Purpose: the domain's service principals (manual 1.6.12.9), read-only, each with its account; a duplicate SPN
                 (which breaks Kerberos for both) flagged.
    Inputs:  v — rendered vars; secrets — fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"spns": [{"spn", "account", "kind", "duplicate"}], "duplicates": [spn]}.
    Fails:   ValidationError from run_op (the DC not reachable).
    Feeds:   agent route GET /v1/domain/kerberos/spns; domain/run_kerberos_command (spns)."""
    return run_op(v, secrets if secrets is not None else load_secrets(), "list_spns", container=container)
