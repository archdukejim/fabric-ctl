import os

import yaml

from fabriclib.common.load_vars import load_vars
from fabriclib.common.paths import SECRETS_FILE
from fabriclib.secrets.common.read_vault_secrets import read_vault_secrets
from fabriclib.secrets.held_secrets import held_read
from fabriclib.secrets.secrets_in_openbao import secrets_in_openbao


def load_secrets(path=SECRETS_FILE, v=None):
    """Purpose: fabric's secrets, wherever they live.
    Inputs:  path — the secrets file, default SECRETS_FILE (/opt/fabric/config/fabric-secrets.yml);
             v — fabric vars for OpenBao, default loaded from vars.yaml next to path (only when needed).
    Returns: dict of secrets: the 0600 file's content ({} if there is neither file nor marker), or
             OpenBao's entry once imported (marker present, no file).
    Fails:   ValidationError from read_vault_secrets (OpenBao unreachable, sealed or refusing);
             yaml.YAMLError for a malformed file; OSError.
    Feeds:   setup/context.py SetupContext.secrets, configure_keycloak, deploy/apply_deployment,
             directory/*, export_secrets,
             run_secrets_command.
    Notes:   a secrets file that was put back (a reinstall restores one) wins over OpenBao and is
             re-imported by the `vault` step. OpenBao failing raises: a missing file must never look like
             "no secrets", or setup would generate new passwords the running services do not know.
    """
    if os.path.exists(path) or not secrets_in_openbao(path):
        if not os.path.exists(path):
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return held_read(lambda: read_vault_secrets(v or load_vars(os.path.join(os.path.dirname(path), "vars.yaml")))[0])
