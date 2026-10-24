import os

from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.dhcp.check_kea_files import check_kea_files
from fabriclib.dhcp.ensure_ddns_zone import ensure_ddns_zone


def deploy_kea(v, secrets, jinja_env, bind_uid, bind_gid):
    """Purpose: Write Kea's files under <deploy_base>/kea during apply: kea-dhcp4.conf and kea-dhcp-ddns.conf, the lease
             folder, the two control-socket folders, and the DHCP subzone's file (created once).
    Inputs:  v — the rendered vars: deploy_base_dir, service_users.kea (uid, gid) and the normalized `dhcp`.
             secrets — fabric's secrets dict (Kea's key: kea_ddns_key, kea_ddns_secret).
             jinja_env — Jinja environment holding kea/*.j2.
             bind_uid, bind_gid — int owner of the subzone file.
    Returns: the set of Kea's configuration files that changed ("kea-dhcp4.conf", "kea-dhcp-ddns.conf"; empty when
             neither did): the daemons to reload (reload_kea, 2.1.10.45).
    Fails:   ValidationError when Kea refuses a changed file (check_kea_files: `kea-dhcp4 -t` in fabric's Kea
             image; nothing is written then; apply_deployment checks first, before installing anything); KeyError
             on missing vars; OSError from makedirs, chown or writing; jinja2 errors while rendering; errors from
             ensure_ddns_zone.
    Feeds:   deploy/deploy_optional_parts (apply), ipam/options/render_kea (the plan poll); tests/kea/run.py,
             tests/kea/reload.py.
    Notes:   config/ is root:kea 0750 and the files root:kea 0640 (the DDNS one holds the TSIG secret); leases/ and run/
             are root 0750, run-ddns/ kea's own 0750 (kea-dhcp-ddns runs as kea and makes its control socket there).
             The subzone file is made only when dhcp.ddns is not false.
    """
    base = os.path.join(v["deploy_base_dir"], "kea")
    kuid, kgid = int(v["service_users"]["kea"]["uid"]), int(v["service_users"]["kea"]["gid"])
    for sub, mode, owner in (("config", 0o750, (0, kgid)), ("leases", 0o750, (0, 0)), ("run", 0o750, (0, 0)),
                             ("run-ddns", 0o750, (kuid, kgid))):
        path = os.path.join(base, sub)
        os.makedirs(path, mode=mode, exist_ok=True)
        os.chown(path, *owner)
        os.chmod(path, mode)
    texts = check_kea_files(v, secrets, jinja_env)   # both checked before either is written
    changed = set()
    for name, text in texts.items():
        if write_file_if_changed(os.path.join(base, "config", name), text, 0o640, 0, kgid):
            changed.add(name)
    if (v.get("dhcp") or {}).get("ddns", True):
        ensure_ddns_zone(v, bind_uid, bind_gid)
    return changed
