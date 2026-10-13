from fabriclib.common.errors import ValidationError
from fabriclib.vault.common.bao_request import bao_request
from fabriclib.vault.ssh.bao_call import bao_call
from fabriclib.vault.ssh.constants import CA_KEY_TYPE, HOST_MOUNT, HOST_ROLE, HOST_ROLE_SETTINGS


def converge_ssh_host_ca(v, token, on):
    """Purpose: bring OpenBao's SSH host CA to the setting (manual 1.6.11.9.6; decision 2.1.7.13), apart from the user
             CA (its own mount, so its own key): on — the engine at HOST_MOUNT, its CA key (made once, inside
             OpenBao) and the role HOST_ROLE (host certificates only, 30 days); off — the role deleted, so nothing
             can be signed, while the engine and its CA key are kept (on again: the same CA clients already trust).
    Inputs:  v — settings (bao_request's); token — a fabric-setup token; on — bool.
    Returns: {"on": bool, "public_key": the host CA's public key line, or "" when the engine was never made}.
    Fails:   ValidationError from bao_call (OpenBao refusing, unreachable, or setup's policy without HOST_MOUNT: run
             the vault step), or when OpenBao makes no CA key.
    Feeds:   vault/ssh/set_ssh_certificates (the console's toggle), setup/setup_openbao (the vault step)."""
    mounts = bao_call(v, token, "GET", "sys/mounts")
    mounted = f"{HOST_MOUNT}/" in mounts or f"{HOST_MOUNT}/" in (mounts.get("data") or {})
    if not mounted and not on:
        return {"on": False, "public_key": ""}
    if not mounted:
        bao_call(v, token, "POST", f"sys/mounts/{HOST_MOUNT}", {
            "type": "ssh", "description": "fabric: SSH host certificates for the managed machines (1.6.11.9.6)"})
    status, data = bao_request(v, "GET", f"{HOST_MOUNT}/config/ca", token=token)
    key = (data.get("data") or {}).get("public_key", "").strip() if status == 200 else ""
    if not on:
        bao_call(v, token, "DELETE", f"{HOST_MOUNT}/roles/{HOST_ROLE}")
        return {"on": False, "public_key": key}
    if not key:
        made = bao_call(v, token, "POST", f"{HOST_MOUNT}/config/ca", {"generate_signing_key": True,
                                                                       "key_type": CA_KEY_TYPE})
        key = (made.get("data") or {}).get("public_key", "").strip()
    bao_call(v, token, "POST", f"{HOST_MOUNT}/roles/{HOST_ROLE}", HOST_ROLE_SETTINGS)
    if not key:
        raise ValidationError("OpenBao made no SSH host CA key")
    return {"on": True, "public_key": key}
