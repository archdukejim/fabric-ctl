from fabriclib.common.jinja_env import jinja_env
from fabriclib.common.load_vars import load_vars
from fabriclib.common.service_user import service_user
from fabriclib.deploy.check_settings import check_settings
from fabriclib.deploy.deploy_paths import deploy_paths
from fabriclib.deploy.render_vars import render_vars
from fabriclib.dhcp.deploy_kea import deploy_kea
from fabriclib.dhcp.reload_kea import reload_kea
from fabriclib.ipam.load_address_plan import load_address_plan


def render_kea(secrets, container="samba", reload=reload_kea):
    """Purpose: Kea alone rendered from the settings and the site's plan, as an apply renders it, and made to take its
             changed configuration (decision 2.1.10.24, manual 1.10.4.26): the plan poll's work. Since 2.1.10.45 Kea
             reloads it over its control socket (reload_kea: `config-reload`, a restart only when a daemon does not
             take it). Never a full apply: no other service, file or DNS zone is touched.
    Inputs:  secrets — fabric's secrets (the agent's password for the plan, Kea's DDNS key); container — the DC's
             container; reload — function(v, changed) -> reload_kea's result (tests give their own).
    Returns: {"changed": bool (Kea's configuration changed and Kea took it), "restarted": bool (it took a restart),
             "subnets": the served networks rendered}.
    Fails:   ValidationError: the settings (render_vars, check_settings), the plan (load_address_plan: none to be had),
             Kea's own check of the new configuration (nothing written then), Kea not healthy after the fallback
             restart (reload_kea); OSError writing the files.
    Feeds:   poll_plan."""
    paths = deploy_paths()
    env = jinja_env(paths["jinja"])
    final_vars, _ = render_vars(env, secrets, load_vars(paths["vars"]))
    load_address_plan(final_vars, secrets, container=container)
    check_settings(final_vars)
    changed = deploy_kea(final_vars, secrets, env, *service_user(final_vars, "bind"))
    took = reload(final_vars, changed) if changed else {"restarted": False}
    return {"changed": bool(changed), "restarted": took["restarted"],
            "subnets": sorted(s["subnet"] for s in (final_vars.get("dhcp") or {}).get("subnets") or [])}
