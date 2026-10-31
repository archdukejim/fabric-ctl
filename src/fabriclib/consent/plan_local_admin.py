from fabriclib.localadmin.common.admin_group import admin_group
from fabriclib.localadmin.constants import SSHD_DROPIN, USER


def plan_local_admin(v):
    """Purpose: what making the fabric host's local-admin changes on the host (manual 1.2.9.3 `local_admin`, 1.7.1.4.1;
             decision 2.1.7.16): the local account, and sshd refusing it over SSH unless the Enterprise Admin turns
             that on in the domain (2.1.7.19). Worded without anything that changes between runs, so an approved plan
             is not asked again.
    Inputs:  v — vars (unused today: every install gets it; kept for the plans' one signature).
    Returns: list of str.
    Fails:   never.
    Feeds:   consent/plan_host_changes, setup/setup_local_admin, undo/undo_group."""
    group = admin_group() or "sudo"
    return [f"the local account {USER} (a home folder, /bin/bash, in the {group} group): the host's break glass, its "
            "password generated and kept by OpenBao, rotated after use, released only to the Enterprise Admin",
            f"{SSHD_DROPIN}, where an SSH server is installed: sshd refuses {USER} (DenyUsers), or lets it in with its "
            "password while the domain's switch for this host is on; checked with `sshd -t` before it is loaded"]
