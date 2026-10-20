import os

import yaml

from fabriclib.common.console import ok
from fabriclib.common.errors import ValidationError
from fabriclib.dns.normalize_tsig_keys import normalize_tsig_keys
from fabriclib.secrets.save_secrets import save_secrets
from fabriclib.setup.errors import SetupError
from fabriclib.setup.name_dc import name_dc


def finish_vars(ctx):
    """Purpose: the last of collecting the settings, after the questions or the menu (and again after the plan's
             [M]enu): the domain controller's name, which fabric chooses (name_dc, 2.1.6.65), embedded TSIG secrets
             moved to the secrets file, and the settings saved as <config>/fabric.yaml.
    Inputs:  ctx — SetupContext: vars (domain, hostname, site_name, tsig_keys, tsig_secrets; changed),
             config_dir, secrets_file, deploy_base, join_invitation (name_dc).
    Returns: path of fabric.yaml (str). dc_name as name_dc leaves it. Embedded TSIG secrets go to the secrets file,
             never into fabric.yaml.
    Fails:   SetupError: invalid tsig_keys, or a secrets file that cannot be written (ValidationError converted);
             name_dc's; OSError writing fabric.yaml.
    Feeds:   setup/collect_vars, setup/choose_plan (after the menu), setup/run_setup (after Advanced's menu)."""
    name_dc(ctx)
    data = ctx.vars
    data["deploy_base_dir"] = ctx.deploy_base
    os.makedirs(ctx.config_dir, mode=0o750, exist_ok=True)
    try:
        data["tsig_keys"], embedded = normalize_tsig_keys(data.get("tsig_keys"), data["domain"],
                                                          data.pop("tsig_secrets", None))
    except ValidationError as e:
        raise SetupError(str(e)) from None
    if embedded:
        try:
            save_secrets({"tsig_secrets": embedded}, ctx.secrets_file)
        except ValidationError as e:
            raise SetupError(str(e)) from None
        ok(f"TSIG secrets for {', '.join(sorted(embedded))} stored with fabric's secrets")
    path = os.path.join(ctx.config_dir, "fabric.yaml")
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)
    os.chmod(path, 0o640)
    ok(f"settings saved to {path}")
    return path
