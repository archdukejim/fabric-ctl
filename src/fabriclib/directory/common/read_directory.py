from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def read_directory(v, secrets=None):
    """Purpose: the domain's devices and device roles (OU=devices, OU=device-roles: 1.6.13.2), raw, in one
             directory read (manual 1.6.3.4).
    Inputs:  v — fabric vars (site_name); secrets — fabric's secrets (default: load_secrets()).
    Returns: {"devices": [{name, type, enabled, macs, owner (DN or ""), description, certs (SHA-256 fingerprints),
             roles (the role names the device carries, fabricRoleName)}], "roles": [{name, description, permissions,
             vlan (int or None), priority (int, default 100), members (device names, computed from the devices'
             roles), dn}]}.
    Fails:   ValidationError from run_op (the directory unreachable or refusing) or load_secrets.
    Feeds:   add_device, update_device, remove_device, require_device, device_overview, list_devices, list_roles."""
    return run_op(v, secrets if secrets is not None else load_secrets(), "read_devices")
