from fabriclib.directory.constants import DIRECTORY_ADMINS
from fabriclib.directory.run_op import run_op
from fabriclib.keycloak.fabric_groups import fabric_groups
from fabriclib.secrets.load_secrets import load_secrets


def list_groups(v, secrets=None, container="samba"):
    """Purpose: the domain's groups (manual 1.6.12.5, the list): each with its kind, member count and description.
    Inputs:  v — rendered vars (ldap_groups); secrets — fabric's secrets (default: load_secrets()); container — the
             DC's container.
    Returns: {"groups": [{"name", "kind", "members", "description"}]}.
    Fails:   ValidationError from run_op (the DC not reachable).
    Feeds:   agent route GET /v1/groups; domain/run_group_command (list)."""
    return run_op(v, secrets if secrets is not None else load_secrets(), "list_groups",
                  {"bundles": sorted(fabric_groups(v) - {DIRECTORY_ADMINS})}, container)
