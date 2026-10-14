from fabriclib.directory.common.privileged_groups import privileged_groups
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def site_roles(v, secrets=None, container="samba"):
    """Purpose: the roles granted at this site and at every site below it (2.1.9.21, manual 1.9.8.20), read from the
             domain: for the Federation tab and `fabricctl federation roles`; never a sibling's or a parent's
             (2.1.9.22).
    Inputs:  v — fabric vars (site_name); secrets — fabric's secrets (default: load_secrets()); container — the DC's
             container.
    Returns: {"sites": [{"site", "own", "roles": [{"role", "kind", "bundle", "group", "exists", "members", "admins",
             "pending"}], "misplaced": [{"uid", "lives", "holds"}]}]} (the DC's list_site_roles; misplaced: people
             holding a role beyond their own level, 2.1.9.24), this site first.
    Fails:   ValidationError from run_op (the DC not reachable) or load_secrets.
    Feeds:   federation_overview, federation/run_federation_command (`roles`)."""
    return run_op(v, secrets if secrets is not None else load_secrets(), "list_site_roles",
                  {"privileged": privileged_groups(v)}, container=container)
