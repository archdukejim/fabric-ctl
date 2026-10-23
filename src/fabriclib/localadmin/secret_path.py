from fabriclib.localadmin.constants import KIND, USER


def secret_path(v):
    """Purpose: where the fabric host's local-admin lives in OpenBao's `local-admin/` mount (manual 1.7.1.3.2,
             1.7.1.4.2): <site>/<kind>/<machine>/<account>.
    Inputs:  v — rendered vars: site_name, hostname.
    Returns: str, e.g. "lan/fabric-host/fabric/local-admin" (without the mount, data/ or metadata/).
    Fails:   KeyError without hostname.
    Feeds:   set_local_admin_password, read_local_admin_secret, remove_local_admin."""
    return f"{(v.get('site_name') or v['hostname']).lower()}/{KIND}/{v['hostname'].lower()}/{USER}"
