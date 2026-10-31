from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def list_host_groups(v, secrets=None, container="samba"):
    """Purpose: the domain's host groups (manual 1.6.11.7), with their machines and the sudo rules that name each.
    Inputs:  v — fabric vars; secrets — fabric's secrets (default: load_secrets()); container — the DC's
             container (tests name their own).
    Returns: list of {"name" (`hosts-<name>`), "short", "machines", "other_members", "rules", "hosts" (the
             host names sudo matches), "fabric"}, by name.
    Fails:   ValidationError from run_op (the DC not reachable or refusing) or load_secrets.
    Feeds:   agent route GET /v1/host-groups (domain:read); directory/run_machines_command (`fabricctl machines
             groups`)."""
    return run_op(v, secrets if secrets is not None else load_secrets(), "list_host_groups", container=container)
