from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def list_machines(v, secrets=None, container="samba"):
    """Purpose: this site's machines in the domain (manual 1.6.7.6, 1.6.5.21 S7.4), Windows and Linux alike.
    Inputs:  v — fabric vars (site_name); secrets — fabric's secrets (default: load_secrets()); container — the DC's
             container (tests name their own).
    Returns: list of {"name", "dns", "os", "type", "sites", "groups" (machine groups), "folder" (its OU's path),
             "enabled", "last_logon", "created", "dn"}, sorted by name.
    Fails:   ValidationError from run_op (the DC not reachable or refusing) or load_secrets.
    Feeds:   samba/domain_overview; agent route GET /v1/machines (Computers, 1.6.12.6); domain/machine_overview."""
    return run_op(v, secrets if secrets is not None else load_secrets(), "list_machines", container=container)
