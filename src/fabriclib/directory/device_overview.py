from fabriclib.directory.common.read_directory import read_directory
from fabriclib.directory.constants import DEVICE_TYPES, PERMISSIONS
from fabriclib.directory.list_devices import list_devices
from fabriclib.directory.list_roles import list_roles
from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.vlan_labels import vlan_labels


def _labels():
    """Purpose: the plan's names for VLAN numbers, from the plan this site last kept (no DC is asked).
    Inputs:  none (load_plan_cache).
    Returns: vlan_labels' dict; {} without a kept plan, or one that cannot be read (only labels are lost: the page
             still shows the numbers).
    Fails:   never.
    Feeds:   device_overview."""
    try:
        return vlan_labels(load_plan_cache())
    except (OSError, ValueError):
        return {}


def device_overview(v):
    """Purpose: Everything the Devices and Roles pages show, from one directory read.
    Inputs:  v — fabric vars (read_directory).
    Returns: {"devices": list_devices, "roles": list_roles, "types": DEVICE_TYPES, "permissions":
             {permission: [what it grants, what enforces it]}, "vlan_labels": {VLAN id: how the address plan names it}
             (vlan_labels of the plan this site last kept, 1.11.1.8; {} without one or when it cannot be read)}.
    Fails:
             run_op's errors (ValidationError: the domain controller not reachable, or refusing).
    Feeds:   agent route GET /v1/devices (agent/ (fabric-agent) Handler.dispatch) -> webui
             agentclient.device_overview -> Devices, Roles and PKI pages.
    """
    directory = read_directory(v)
    return {"devices": list_devices(v, directory), "roles": list_roles(v, directory),
            "types": DEVICE_TYPES, "permissions": {k: list(p) for k, p in PERMISSIONS.items()},
            "vlan_labels": _labels()}
