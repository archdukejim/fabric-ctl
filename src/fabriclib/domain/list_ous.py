from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def list_ous(v, secrets=None, container="samba"):
    """Purpose: the tree of the domain's folders (manual 1.6.12.7): every OU, fabric's marked, what each holds as
                 counts.
    Inputs:  v — rendered vars; secrets — fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"ous": [{"path", "dn", "fabric", "own", "holds"}]}.
    Fails:   ValidationError from run_op (the DC not reachable).
    Feeds:   agent route GET /v1/ous; domain/run_ou_command (list)."""
    return run_op(v, secrets if secrets is not None else load_secrets(), "list_ous", container=container)
