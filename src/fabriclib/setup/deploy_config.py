import os

import yaml

from fabriclib.common.console import ok
from fabriclib.deploy.apply_deployment import apply_deployment
from fabriclib.secrets.secrets_in_openbao import secrets_in_openbao

CLI_WRAPPER = """#!/bin/bash
# fabricctl - fabric management CLI (installed by fabricctl setup)
if [[ " $* " == *" --version "* ]]; then
  exec bash "{target}/lib/manage.sh" --version
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "Please run as root (sudo fabricctl)"
  exit 1
fi
exec bash "{target}/lib/manage.sh" "$@"
"""


PACKAGED_CLI = "/usr/bin/fabricctl"
LOCAL_CLI = "/usr/local/bin/fabricctl"


def _packaged():
    """Purpose: whether fabricctl is installed from the .deb (it owns /usr/bin/fabricctl).
    Inputs:  none (reads PACKAGED_CLI).
    Returns: True when /usr/bin/fabricctl exists and contains "installed by the fabricctl package".
    Fails:   OSError/UnicodeDecodeError if the file exists but cannot be read as text.
    Feeds:   run."""
    return os.path.exists(PACKAGED_CLI) and "installed by the fabricctl package" in open(PACKAGED_CLI).read()


def _write_exec(path, text):
    """Purpose: write an executable script.
    Inputs:  path — destination; text — file content.
    Returns: None; the file is written and chmod 0755.
    Fails:   OSError on write or chmod.
    Feeds:   run (the /usr/local/bin/fabricctl wrapper)."""
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o755)


def run(ctx):
    """Purpose: render every template and deploy config, compose files, systemd units and web assets without
             starting anything; make sure a `fabricctl` command exists.
    Inputs:  ctx — SetupContext: vars (saved to <config>/fabric.yaml first, keeping plan choices), config_dir,
             secrets_file, deploy_base, target_dir. Sets env DEPLOY_BASE_DIR, CUSTOM_VARS_PATH,
             SECRETS_FILE_OVERRIDE, LINK_VARS_PATH for the deploy engine (deploy/deploy_paths reads them per run).
    Returns: None. Leaves the rendered install, an empty 0600 secrets file unless the secrets are in OpenBao,
             ctx.restart_services extended with services whose config, unit or image changed, ctx reloaded
             (vars.yaml). From the package: an old /usr/local/bin wrapper is removed; from a checkout:
             /usr/local/bin/fabricctl is written (runs <target>/lib/manage.sh).
    Fails:   whatever apply_deployment raises (ValidationError, CalledProcessError, OSError) —
             propagates; OSError writing files.
    Feeds:   setup step `deploy`, run by run_setup via STEPS (run_setup then reloads ctx.vars)."""
    fabric_yaml = os.path.join(ctx.config_dir, "fabric.yaml")
    with open(fabric_yaml, "w") as f:           # persist plan choices made after collect_vars
        yaml.safe_dump(ctx.vars, f, sort_keys=False)

    # Secrets are created in the install, never in a git checkout. Once they
    # live in OpenBao no file is created: an empty one would read as "none".
    if not secrets_in_openbao(ctx.secrets_file):
        if not os.path.exists(ctx.secrets_file):
            open(ctx.secrets_file, "a").close()
        os.chmod(ctx.secrets_file, 0o600)

    os.environ.update({
        "DEPLOY_BASE_DIR": ctx.deploy_base,
        "CUSTOM_VARS_PATH": fabric_yaml,
        "SECRETS_FILE_OVERRIDE": ctx.secrets_file,
        "LINK_VARS_PATH": os.path.join(ctx.config_dir, "link-vars.yaml"),
    })
    # Services whose config, unit or image changed: the start step restarts them.
    ctx.restart_services.update(apply_deployment(start_services=False) or ())
    ctx.load_state()
    ok(f"configuration deployed to {ctx.deploy_base}")

    if _packaged():
        # The package's /usr/bin/fabricctl is the command; a checkout-era
        # wrapper in /usr/local/bin would shadow it (it comes first in PATH).
        if os.path.exists(LOCAL_CLI) and "installed by fabricctl setup" in open(LOCAL_CLI).read():
            os.remove(LOCAL_CLI)
        ok(f"fabricctl command: {PACKAGED_CLI} (package)")
    else:
        _write_exec(LOCAL_CLI, CLI_WRAPPER.format(target=ctx.target_dir))
        ok(f"installed {LOCAL_CLI}")
