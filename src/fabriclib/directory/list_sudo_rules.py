from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def list_sudo_rules(v, secrets=None, container="samba"):
    """Purpose: the sudo rules of this site (manual 1.6.11.7), each marked by who made it: fabric's editor (`fabric`,
             removable with it), the site's default rule (`default`, 1.6.11.3) or an admin's own (`other`, read-only
             here).
    Inputs:  v — fabric vars (site_name); secrets — fabric's secrets (default: load_secrets()); container — the DC's
             container.
    Returns: list of {"name", "kind", "users", "commands", "run_as", "hosts", "host_group"}, by name.
    Fails:   ValidationError from run_op (the DC not reachable or refusing) or load_secrets.
    Feeds:   agent route GET /v1/sudo (domain:read); directory/run_sudo_command (`fabricctl sudo list`)."""
    return run_op(v, secrets if secrets is not None else load_secrets(), "list_sudo_rules", container=container)
