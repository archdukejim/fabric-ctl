import os

from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.dhcp.check_kea_files import check_kea_files
from fabriclib.dhcp.ensure_ddns_zone import ensure_ddns_zone


def deploy_kea(v, secrets, jinja_env, bind_uid, bind_gid):
    """Purpose: Write Kea's files under <deploy_base>/kea during apply: kea-dhcp4.conf and kea-dhcp-ddns.conf, the lease
             folder, the control-socket folder, and the DHCP subzone's file (created once).
    Inputs:  v — the rendered vars: deploy_base_dir, service_users.kea.gid and the normalized `dhcp`.
             secrets — fabric's secrets dict (kea_ddns_secret).
             jinja_env — Jinja environment holding kea/*.j2.
             bind_uid, bind_gid — int owner of the subzone file.
    Returns: True if either Kea config file changed (Kea must be restarted), else False.
    Fails:   ValidationError when Kea refuses a changed file (check_kea_files: `kea-dhcp4 -t` in fabric's Kea
             image; nothing is written then; apply_deployment checks first, before installing anything); KeyError
             on missing vars; OSError from makedirs, chown or writing; jinja2 errors while rendering; errors from
             ensure_ddns_zone.
    Feeds:   deploy/deploy_optional_parts (apply); tests/kea/run.py.
    Notes:   config/ is root:kea 0750 and the files root:kea 0640 (the DDNS one holds the TSIG secret); leases/ and run/
             are root 0750. The subzone file is made only when dhcp.ddns is not false.
    """
    base = os.path.join(v["deploy_base_dir"], "kea")
    kgid = int(v["service_users"]["kea"]["gid"])
    for sub, mode, owner in (("config", 0o750, (0, kgid)), ("leases", 0o750, (0, 0)), ("run", 0o750, (0, 0))):
        path = os.path.join(base, sub)
        os.makedirs(path, mode=mode, exist_ok=True)
        os.chown(path, *owner)
        os.chmod(path, mode)
    texts = check_kea_files(v, secrets, jinja_env)   # both checked before either is written
    changed = False
    for name, text in texts.items():
        changed |= write_file_if_changed(os.path.join(base, "config", name), text, 0o640, 0, kgid)
    if (v.get("dhcp") or {}).get("ddns", True):
        ensure_ddns_zone(v, bind_uid, bind_gid)
    return changed
