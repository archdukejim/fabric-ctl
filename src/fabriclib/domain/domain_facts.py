from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def domain_facts(v, secrets=None, container="samba"):
    """Purpose: the domain's functional level and its domain controllers, writable or read-only (manual 1.6.12.3).
    Inputs:  v — rendered vars; secrets — fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"level", "dcs": [{"name", "dns", "writable"}]}.
    Fails:   ValidationError from run_op (the DC not reachable).
    Feeds:   directory_overview."""
    return run_op(v, secrets if secrets is not None else load_secrets(), "domain_facts", container=container)
