import os

from fabriclib.directory.constants import DEFAULT_DEVICE_ROLES
from fabriclib.directory.run_op import run_op


def ensure_default_device_roles(v, secrets, marker, container="samba"):
    """Purpose: fabric's default device roles (DEFAULT_DEVICE_ROLES) in the domain's OU=device-roles, created
             once: on a new install. The marker keeps a default role the admin deleted or renamed from coming back.
    Inputs:  v — fabric vars (site_name: the root site); secrets — fabric's secrets (ad_agent_password); marker —
             path of the file that records they were made; container — the DC's container (tests name their own).
    Returns: list of the role names added (empty when the marker exists or they all are).
    Fails:   ValidationError from run_op (the directory unreachable or refusing); OSError writing the marker.
    Feeds:   setup/start_services (the root site)."""
    if os.path.exists(marker):
        return []
    have = {r["name"] for r in run_op(v, secrets, "read_devices", container=container)["roles"]}
    added = []
    for name, permissions, description in DEFAULT_DEVICE_ROLES:
        if name in have:
            continue
        run_op(v, secrets, "save_role", {"name": name, "description": description, "permissions": permissions,
                                         "vlan": None, "priority": 100, "new": True}, container)
        added.append(name)
    with open(marker, "w") as f:
        f.write("\n".join(added) + "\n")
    return added
