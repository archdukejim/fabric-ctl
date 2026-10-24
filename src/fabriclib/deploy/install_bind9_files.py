import os

from fabriclib.common.copy_tree_with_perms import copy_tree_with_perms
from fabriclib.common.ensure_dir import ensure_dir
from fabriclib.common.service_user import service_user
from fabriclib.dns.find_changed_zones import find_changed_zones
from fabriclib.dns.served_serial import served_serial


def install_bind9_files(paths, final_vars):
    """Purpose: BIND's folders and configuration; find the zones whose records changed (installed later, the safe
             way for the state BIND is in).
    Inputs:  paths — deploy_paths() (base, render); final_vars — rendered settings (service_users.bind).
    Returns: {"config": True if the configuration changed, "zones": [(zone, src, dst)] changed zones}.
    Fails:   OSError from creating folders, copying or chmod.
    Feeds:   apply_deployment (then install_zones_and_restart or finish_without_start).
    Notes:   named.conf.keys and rndc.key hold secrets: 0600."""
    uid, gid = service_user(final_vars, "bind")
    base, out = paths["base"], paths["render"]
    for d in ("config", "data", "log", "cache"):
        ensure_dir(os.path.join(base, "bind9", d), 0o750, uid, gid)
    config = copy_tree_with_perms(os.path.join(out, "bind9/config"), os.path.join(base, "bind9/config"),
                                  uid, gid, 0o640, 0o750)
    zones = find_changed_zones(os.path.join(out, "bind9/data"), os.path.join(base, "bind9/data"), served=served_serial)
    for secret_file in ("named.conf.keys", "rndc.key"):
        os.chmod(os.path.join(base, "bind9/config", secret_file), 0o600)
    return {"config": config, "zones": zones}
