import copy
import grp
import os
import shutil

import yaml

from fabriclib.common.errors import ValidationError
from fabriclib.common.jinja_env import jinja_env as jinja_env_for
from fabriclib.common.load_vars import load_vars
from fabriclib.deploy.archive_vars import archive_vars
from fabriclib.deploy.check_fixed_identity import check_fixed_identity
from fabriclib.deploy.check_rendered import check_rendered
from fabriclib.deploy.generate_missing_secrets import generate_missing_secrets
from fabriclib.deploy.load_link_vars import load_link_vars
from fabriclib.deploy.merge_radius_clients import merge_radius_clients
from fabriclib.deploy.merge_tsig_keys import merge_tsig_keys
from fabriclib.deploy.render_templates import render_templates
from fabriclib.deploy.render_vars import render_vars
from fabriclib.deploy.service_units import service_units
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.secrets.save_secrets import save_secrets


def _prepare(paths):
    """Purpose: everything up to the render: secrets, the checked settings and the render context (check_rendered,
             shared with the quick zone path: 2.1.4.7).
    Inputs:  paths — deploy_paths().
    Returns: dict with secrets, final_vars, context, tsig_keys, jinja_env, reverse (reverse_zones()).
    Fails:   ValidationError (settings, secrets that cannot be loaded or saved, fixed identity).
    Feeds:   render_deployment."""
    custom_vars = load_vars(paths["vars"])
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
    # the settings check and BIND's zone-list context: shared with the quick zone path (dns/publish_zone_list, 2.1.4.7)
    checked = check_rendered(final_vars, secrets, context, paths["federation"])
    return {"secrets": secrets, "final_vars": final_vars, "context": context, "tsig_keys": tsig_keys,
            "jinja_env": jinja_env, "reverse": checked["reverse"]}


def render_deployment(paths):
    """Purpose: the render half of the deploy engine: secrets made and saved, the settings checked, and every template
             rendered into the render folder; nothing is installed (moved here from apply_deployment for DNS' Apply,
             decision 2.1.8.24).
    Inputs:  paths — deploy_paths().
    Returns: dict: secrets, final_vars, context (with final_vars and the link vars), tsig_keys, jinja_env, reverse,
             units (service_units()).
    Fails:   ValidationError (settings, secrets that cannot be loaded or saved, fixed identity, a template that does
             not render); OSError writing the render folder.
    Feeds:   apply_deployment (then installs everything), dns/apply_dns (then installs BIND's files and the landing
             page)."""
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
    reverse = p["reverse"]                 # with reverse_zone_names and federation_links (check_rendered)
    print("Rendering Jinja2 templates...")
    render_templates(paths, jinja_env, context, final_vars, secrets, p["tsig_keys"], units, reverse)
    return {**p, "units": units}
