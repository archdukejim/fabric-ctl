import copy
import grp
import os
import shutil
import sys

import yaml

from fabriclib.common.errors import ValidationError
from fabriclib.common.jinja_env import jinja_env as jinja_env_for
from fabriclib.common.load_vars import load_vars
from fabriclib.common.service_user import service_user
from fabriclib.consent.allowed_to_change import allowed_to_change
from fabriclib.consent.plan_services import plan_services
from fabriclib.deploy.archive_vars import archive_vars
from fabriclib.deploy.check_fixed_identity import check_fixed_identity
from fabriclib.deploy.check_rendered import check_rendered
from fabriclib.deploy.deploy_optional_parts import deploy_optional_parts
from fabriclib.deploy.deploy_paths import deploy_paths
from fabriclib.deploy.finish_without_start import finish_without_start
from fabriclib.deploy.generate_missing_secrets import generate_missing_secrets
from fabriclib.deploy.install_bind9_files import install_bind9_files
from fabriclib.deploy.install_fabric_tree import install_fabric_tree
from fabriclib.deploy.install_nginx_config import install_nginx_config
from fabriclib.deploy.install_openbao_config import install_openbao_config
from fabriclib.deploy.install_runtime_dirs import install_runtime_dirs
from fabriclib.deploy.install_service_units import install_service_units
from fabriclib.deploy.install_stepca_templates import install_stepca_templates
from fabriclib.deploy.install_timers import install_timers
from fabriclib.dhcp.keep_hand_set_addresses import keep_hand_set_addresses
from fabriclib.deploy.install_webui_files import install_webui_files
from fabriclib.deploy.keep_old_install import keep_old_install
from fabriclib.deploy.load_link_vars import load_link_vars
from fabriclib.deploy.merge_radius_clients import merge_radius_clients
from fabriclib.deploy.merge_tsig_keys import merge_tsig_keys
from fabriclib.deploy.render_templates import render_templates
from fabriclib.deploy.render_vars import render_vars
from fabriclib.deploy.restart_changed import restart_changed
from fabriclib.deploy.service_units import service_units
from fabriclib.deploy.verify_published_images import verify_published_images
from fabriclib.federation.deploy_federation_endpoint import deploy_federation_endpoint
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.secrets.save_secrets import save_secrets


def _prepare(paths):
    """Purpose: everything up to the render: secrets, the checked settings (the DHCP subnets and static names from the
             site's address plan in the domain, manual 1.10.4.14) and the render context (check_rendered, shared with
             the quick zone path: 2.1.4.7, 2.1.10.21).
    Inputs:  paths — deploy_paths().
    Returns: dict with secrets, final_vars, context, tsig_keys, jinja_env, reverse (reverse_zones()).
    Fails:   ValidationError (settings, secrets that cannot be loaded or saved, fixed identity).
    Feeds:   apply_deployment."""
    custom_vars = load_vars(paths["vars"])
    for line in keep_old_install(custom_vars):     # an install from before 0.7.0, applied before setup ran (2.1.6.45)
        print(line)
    try:
        secrets = load_secrets(paths["secrets"])
    except ValidationError as e:
        raise ValidationError(f"{e}\nfabric's secrets are in OpenBao: unlock it (plug in an unlock device) and run "
                              "again.")
    loaded = copy.deepcopy(secrets)
    changed = generate_missing_secrets(secrets)
    tsig_keys, tsig_changed = merge_tsig_keys(custom_vars, secrets)
    radius_changes = merge_radius_clients(custom_vars, secrets)
    if changed or tsig_changed or radius_changes:
        update = {k: val for k, val in secrets.items() if loaded.get(k) != val}
        if "radius_secrets" in update:            # merged key by key: removals must be explicit
            update["radius_secrets"] = radius_changes
        save_secrets(update, paths["secrets"])

    jinja_env = jinja_env_for(paths["jinja"])
    final_vars, context = render_vars(jinja_env, secrets, custom_vars)
    archive_vars(paths["target"])
    check_fixed_identity(final_vars, paths["config"])
    # the plan's subnets and static names (1.10.4.14), the settings check and BIND's zone-list context: shared with
    # the quick zone path (dns/publish_zone_list, 2.1.4.7,
    # 2.1.10.21)
    checked = check_rendered(final_vars, secrets, context, paths["federation"])
    for line in checked["lines"]:
        print(line)
    return {"secrets": secrets, "final_vars": final_vars, "context": context, "tsig_keys": tsig_keys,
            "jinja_env": jinja_env, "reverse": checked["reverse"]}


def _deploy(paths, start_services):
    """Purpose: the deploy engine's steps in order (see apply_deployment).
    Inputs:  paths — deploy_paths(); start_services — bool.
    Returns: the set of units whose configuration changed (restarted already when start_services).
    Fails:   ValidationError for every refusal; OSError and CalledProcessError from the steps.
    Feeds:   apply_deployment."""
    p = _prepare(paths)
    secrets, final_vars, context, jinja_env = p["secrets"], p["final_vars"], p["context"], p["jinja_env"]

    out = paths["render"]
    if os.path.exists(out):
        shutil.rmtree(out)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "vars.yaml"), "w") as f:
        yaml.safe_dump(final_vars, f, default_flow_style=False)
    context.update(final_vars)
    try:                                   # Fluent Bit reads the journal through this group
        context.setdefault("journal_gid", grp.getgrnam("systemd-journal").gr_gid)
    except KeyError:
        pass
    load_link_vars(paths, jinja_env, context)
    units = service_units(paths["base"], final_vars)
    reverse = p["reverse"]                 # with reverse_zone_names, reverse_by_hand, federation_links (check_rendered)
    print("Rendering Jinja2 templates...")
    render_templates(paths, jinja_env, context, final_vars, secrets, p["tsig_keys"], units, reverse)
    if verify_published_images(paths, final_vars):  # nothing installed yet: a refusal changes nothing
        print("Signatures of fabric's published images: verified")

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
    optional = deploy_optional_parts(paths, final_vars, secrets, jinja_env, context["federation_links"])
    restart |= optional["restart"]
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
             "webui": web["webui"], "agent": web["agent"], "federation_unit": fed["unit_changed"]}
    bind_ids = service_user(final_vars, "bind")
    if not start_services:
        return finish_without_start(paths, state, bind_ids)
    return restart_changed(paths, final_vars, secrets, state, bind_ids)


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
             dns_filter; host_ram_capacity under 4; site_name, org_domain or
             ldap_base_dn not valid or not what they were at install; a template that does not render; an image
             build that fails (start_services=False); BIND9 refusing `rndc reconfig`; a published image
             whose signature does not verify (verify_published_images); fabric's own units (the
             `services` host change) not approved — an install set up before consent existed is not refused. A bad
             link-vars file is only
             reported. OSError from file operations propagates.
    Feeds:   lib/deploy.py (`python3 deploy.py`, fabriclib/setup/deploy_config.py, images/switch_image.py),
             menu/apply_and_report (`fabricctl --apply`, the vars editor, system/apply_changes.py for the web UI).
    Notes:   no --pull on image builds: apply never takes a new base image implicitly. The deployed vars are archived
             to <fabric>/archive/<stamp>-vars.yaml before being replaced."""
    print("Starting native Python deployment...")
    paths = deploy_paths()
    try:
        if not allowed_to_change(paths["config"], "services", plan_services(), unasked_install=True):
            raise ValidationError("fabric's own services (systemd units) are not approved on this host: "
                                  "`sudo fabricctl setup` asks (manual 1.2.9)")
        return _deploy(paths, start_services)
    except ValidationError as e:
        print(f"Error: {e}")
        sys.exit(1)
