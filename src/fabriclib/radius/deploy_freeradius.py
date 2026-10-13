import os

from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.radius.nas.policy_clients import policy_clients
from fabriclib.radius.nas.profiles import RADSEC_CN_PREFIX

CONFIG_FILES = ["radiusd.conf", "clients.conf", "fabric-radius.json", "mods/always", "mods/eap", "mods/fabric_policy",
                "mods/mschap", "sites/fabric", "sites/radsec", "sites/check-eap-tls", "sites/inner-tunnel"]


def deploy_freeradius(v, secrets, jinja_env):
    """Purpose: Write FreeRADIUS's files under <deploy_base>/freeradius during apply: the configuration (config/) and
             fabric's policy code (python/).
    Inputs:  v — the rendered vars: deploy_base_dir, service_users.freeradius uid/gid and what the templates use.
             secrets — fabric's secrets dict (radius_secrets, ad_radius_password).
             jinja_env — Jinja environment whose first search path holds freeradius/config/*.j2 and
             freeradius/python/*.py.
    Returns: True if any file changed, else False.
    Fails:   KeyError on missing vars; OSError from makedirs, chown, listing or writing; jinja2 errors while rendering;
             ValidationError from policy_clients for a client with an unknown vendor.
    Feeds:   deploy/deploy_optional_parts (apply); tests/freeradius/run.py.
    Notes:   config files are root:freerad 0640 (clients.conf holds the RADIUS secrets, ad-password the site's
             fabric-radius account's). certs/ (server.pem, server.key and ca.pem, the fabric CA that client
             certificates and the DC must chain to) is only created here; setup's certificate step fills it.
             fabric-radius.json carries each client's vendor rules (policy_clients, manual 1.11.1.2); sites/radsec
             is empty while no client uses RadSec (1.11.1.3).
    """
    base = os.path.join(v["deploy_base_dir"], "freeradius")
    gid = int(v["service_users"]["freeradius"]["gid"])
    uid = int(v["service_users"]["freeradius"]["uid"])
    for sub, owner in (("config", (0, gid)), ("config/mods", (0, gid)), ("config/sites", (0, gid)),
                       ("python", (0, gid)), ("certs", (uid, gid))):
        path = os.path.join(base, sub)
        os.makedirs(path, mode=0o750, exist_ok=True)
        os.chown(path, *owner)
        os.chmod(path, 0o750)
    ctx = {**v, "radius_secrets": secrets.get("radius_secrets") or {},
           "radius_policy_clients": policy_clients(v.get("radius_clients")), "radsec_cn_prefix": RADSEC_CN_PREFIX}
    changed = False
    for name in CONFIG_FILES:
        text = jinja_env.get_template(f"freeradius/config/{name}.j2").render(**ctx)
        changed |= write_file_if_changed(os.path.join(base, "config", name), text, 0o640, 0, gid)
    changed |= write_file_if_changed(os.path.join(base, "config", "ad-password"),
                                     secrets.get("ad_radius_password", "") + "\n", 0o640, 0, gid)
    src = os.path.join(jinja_env.loader.searchpath[0], "freeradius", "python")
    if not os.path.isdir(src):              # a checkout: the policy is code, in src/containers/ (manual 1.2.2)
        src = os.path.join(os.path.dirname(jinja_env.loader.searchpath[0]), "src", "containers", "freeradius")
    for name in sorted(os.listdir(src)):
        if name.endswith(".py"):
            changed |= write_file_if_changed(os.path.join(base, "python", name),
                                             open(os.path.join(src, name)).read(), 0o640, 0, gid)
    return changed
