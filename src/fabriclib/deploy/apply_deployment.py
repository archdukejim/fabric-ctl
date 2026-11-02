import sys

from fabriclib.common.apply_intent import apply_intent
from fabriclib.common.errors import ValidationError
from fabriclib.common.service_user import service_user
from fabriclib.consent.allowed_to_change import allowed_to_change
from fabriclib.consent.plan_services import plan_services
from fabriclib.deploy.deploy_optional_parts import deploy_optional_parts
from fabriclib.deploy.deploy_paths import deploy_paths
from fabriclib.deploy.finish_without_start import finish_without_start
from fabriclib.deploy.install_bind9_files import install_bind9_files
from fabriclib.deploy.install_fabric_tree import install_fabric_tree
from fabriclib.deploy.install_nginx_config import install_nginx_config
from fabriclib.deploy.install_openbao_config import install_openbao_config
from fabriclib.deploy.install_runtime_dirs import install_runtime_dirs
from fabriclib.deploy.install_service_units import install_service_units
from fabriclib.deploy.install_stepca_templates import install_stepca_templates
from fabriclib.deploy.install_timers import install_timers
from fabriclib.deploy.install_webui_files import install_webui_files
from fabriclib.deploy.render_deployment import render_deployment
from fabriclib.deploy.renew_landing_cert import renew_landing_cert
from fabriclib.deploy.restart_changed import restart_changed
from fabriclib.deploy.verify_published_images import verify_published_images
from fabriclib.dhcp.check_kea_files import check_kea_files
from fabriclib.dhcp.kea_key.drop_old_key import drop_old_key
from fabriclib.dns.changed_names import changed_names
from fabriclib.dhcp.keep_hand_set_addresses import keep_hand_set_addresses
from fabriclib.federation.deploy_federation_endpoint import deploy_federation_endpoint
from fabriclib.ipam.options.watch_state import save_watch_state


def _kea_steps(p, changed, restart, start_services):
    """Purpose: what the end of the apply does for Kea: a changed file reloaded over its control socket once BIND took
             its part (2.1.10.45), or Kea restarted when its unit or image changed too, or left for setup's start
             step; while its DNS key is being replaced (2.1.10.42), kea-dhcp-ddns made to run on the new key (even
             when an apply that stopped before wrote its file) and then BIND's old key dropped.
    Inputs:  p — render_deployment's result (final_vars, context, jinja_env, kea_old); changed — Kea's files that
             changed (deploy_kea's); restart — the units to restart, changed in place ("kea" added); start_services
             — bool.
    Returns: (the files to reload: set, the old key's drop: function() -> its name, or None).
    Fails:   never.
    Feeds:   _deploy."""
    final_vars = p["final_vars"]
    reload = set()
    if changed and (not start_services or "kea" in restart):
        restart.add("kea")
    else:
        reload = set(changed)
    on = final_vars.get("install_kea") and (final_vars.get("dhcp") or {}).get("ddns", True)
    if not (p["kea_old"] and start_services and on):
        return reload, None
    if "kea" not in restart:
        reload.add("kea-dhcp-ddns.conf")
    return reload, lambda: drop_old_key(final_vars, p["context"], p["jinja_env"], p["kea_old"])


def _deploy(paths, start_services):
    """Purpose: the deploy engine's steps in order (see apply_deployment).
    Inputs:  paths — deploy_paths(); start_services — bool.
    Returns: the set of units whose configuration changed (restarted already when start_services); with
             start_services, nginx too when the landing page's certificate was issued again (renew_landing_cert).
    Fails:   ValidationError for every refusal; OSError and CalledProcessError from the steps.
    Feeds:   apply_deployment."""
    p = render_deployment(paths, rotate=start_services)
    secrets, final_vars, context, jinja_env = p["secrets"], p["final_vars"], p["context"], p["jinja_env"]
    units, out = p["units"], paths["render"]
    if verify_published_images(paths, final_vars):  # nothing installed yet: a refusal changes nothing
        print("Signatures of fabric's published images: verified")
    if final_vars.get("install_kea"):               # Kea checks its files before anything is installed (2.3.10.11.16)
        check_kea_files(final_vars, secrets, jinja_env)

    print("Deploying configurations...")
    install_fabric_tree(paths, final_vars)
    svc = install_service_units(paths, final_vars, units)
    restart = svc["restart"]
    for name in sorted(svc["stopped"]):
        print(f"  {name}: turned off, stopped and removed (its data is kept)")
    if install_openbao_config(paths, final_vars):
        restart.add("openbao")
    ngx = install_nginx_config(paths, final_vars)
    bind = install_bind9_files(paths, final_vars)
    names = changed_names(bind["zones"])      # before the swap: the resolver forgets them (2.1.10.46, 2.1.4.9)
    optional = deploy_optional_parts(paths, final_vars, secrets, jinja_env, context["federation_links"])
    restart |= optional["restart"]
    kea_reload, kea_drop = _kea_steps(p, optional["kea"], restart, start_services)
    web = install_webui_files(paths, final_vars)
    fed = deploy_federation_endpoint(final_vars, out, paths["base"])   # host unit + nginx's socket folder, or removal
    if install_stepca_templates(paths, final_vars):
        restart.add("stepca")
    install_runtime_dirs(paths, final_vars, p["tsig_keys"])
    install_timers(paths, final_vars)
    keep_hand_set_addresses(final_vars)    # for the hourly cleanup of DHCP names left behind (2.1.10.22)

    state = {"restart": restart, "rebuild": svc["rebuild"],
             "daemon_reload": svc["daemon_reload"] or ngx["daemon_reload"] or web["agent"]
             or fed["unit_changed"] or fed["removed"],
             "bind9_config": bind["config"], "zones": bind["zones"], "nginx": ngx["nginx"],
             "webui": web["webui"], "agent": web["agent"], "federation_unit": fed["unit_changed"],
             "kea_reload": kea_reload, "kea_drop": kea_drop, "names": names}
    bind_ids = service_user(final_vars, "bind")
    if not start_services:
        changed = finish_without_start(paths, state, bind_ids)
    else:
        changed = restart_changed(paths, final_vars, secrets, state, bind_ids)
        # the landing page's names follow the zone: a changed alias gets its certificate now; the old one expires
        # (2.1.4.8)
        if renew_landing_cert(paths, final_vars):
            changed.add("nginx")
    if p["dns_digest"] is not None:        # BIND took this plan's names: only now may the poll count DNS current
        save_watch_state("plan-dns", {"dns": p["dns_digest"]})
    return changed


def apply_deployment(start_services=True):
    """Purpose: the deploy engine: render every template from the vars file and secrets into /tmp/fabric-render, copy
             what changed into the deploy base and /etc/systemd/system, then reload or restart what is affected.
             Missing secrets (CA, rndc, the domain's accounts, Keycloak, Kea, OIDC, the resolver, TSIG, RADIUS) are
             generated once and saved.
    Inputs:  start_services — bool, default True. False (first install, `fabricctl setup` via
             fabriclib/setup/deploy_config.py): files are deployed, changed images built and zones swapped safely, but
             no service is started, restarted or reloaded (certificates may not exist yet). Paths from deploy_paths()
             (env DEPLOY_BASE_DIR, CUSTOM_VARS_PATH, SECRETS_FILE_OVERRIDE, LINK_VARS_PATH, read at call time). Must run
             as root.
    Returns: set of systemd units whose configuration changed. With start_services=True they have been restarted
             (fabric-web and fabric-agent queued with --no-block); with False, the caller restarts them.
    Fails:   sys.exit(1) after an "Error: …" line for every refusal (ValidationError): secrets that cannot be loaded
             (OpenBao locked) or saved; invalid TSIG keys, ACL policies, RADIUS clients/people, DHCP or time settings,
             dns_filter; DHCP on with its subnets in the address plan and no plan to be had (the DC not answering
             and none kept, load_address_plan); host_ram_capacity under 4; site_name, org_domain or
             ldap_base_dn not valid or not what they were at install; a template that does not render; an image
             build that fails (start_services=False); BIND9 refusing `rndc reconfig`; BIND refusing to delete a DHCP
             name left behind (restart_changed, 2.1.10.22, raised once the rest is done); the landing page's certificate
             not issued again for changed names (renew_landing_cert, 2.1.4.8, after everything else is applied); a
             published image whose signature does not verify (verify_published_images); fabric's own units (the
             `services` host change) not approved — an install set up before consent existed is not refused. A bad
             link-vars file is only
             reported. OSError from file operations propagates.
    Feeds:   lib/deploy.py (`python3 deploy.py`, fabriclib/setup/deploy_config.py, images/switch_image.py),
             menu/apply_and_report (`fabricctl --apply`, the vars editor, system/apply_changes.py for the web UI).
    Notes:   no --pull on image builds: apply never takes a new base image implicitly. The apply intent is held
             throughout (common/apply_intent), so the plan poll does not render Kea beside it (2.1.10.45). The
             deployed vars are archived to <fabric>/archive/<stamp>-vars.yaml before being replaced."""
    print("Starting native Python deployment...")
    paths = deploy_paths()
    try:
        if not allowed_to_change(paths["config"], "services", plan_services(), unasked_install=True):
            raise ValidationError("fabric's own services (systemd units) are not approved on this host: "
                                  "`sudo fabricctl setup` asks (manual 1.2.9)")
        with apply_intent():                # the plan poll leaves Kea to this apply (2.1.10.45)
            return _deploy(paths, start_services)
    except ValidationError as e:
        print(f"Error: {e}")
        sys.exit(1)
