from fabriclib.common.errors import ValidationError
from fabriclib.secrets.constants import VAULT_PATH
from fabriclib.secrets.held_secrets import forget_secrets
from fabriclib.vault.common.approle_login import approle_login
from fabriclib.vault.common.bao_request import bao_request
from fabriclib.vault.constants import SETUP_CREDS


def write_vault_secrets(v, secrets, version, token=None):
    """Purpose: Store fabric's secrets as a new KV v2 version, only if the stored version is still the one
             read (check-and-set).
    Inputs:  v — fabric vars for OpenBao; secrets — the complete dict to store; version — int, the version
             read (0: only if the entry does not exist yet); token — default a SETUP_CREDS AppRole login.
    Returns: the new version (int).
    Fails:   ValidationError "writing fabric's secrets to OpenBao failed: ..." (including a check-and-set
             conflict: a concurrent change is refused, never overwritten);
             approle_login's ValidationError ("<path> is missing: run ...", "OpenBao refused the
             setup-approle.json login: ..."); bao_request's "OpenBao is not reachable at ...".
    Feeds:   save_secrets, import_secrets.
    """
    token = token or approle_login(v, SETUP_CREDS)
    mount, _, name = VAULT_PATH.partition("/")
    status, data = bao_request(v, "POST", f"{mount}/data/{name}", token=token,
                               body={"options": {"cas": int(version)}, "data": secrets})
    if status != 200:
        raise ValidationError(f"writing fabric's secrets to OpenBao failed: {data.get('errors') or status}")
    forget_secrets()
    return int(data["data"]["version"])
