from fabriclib.common.errors import ValidationError
from fabriclib.vault.common.bao_request import bao_request
from fabriclib.vault.ssh.bao_call import bao_call
from fabriclib.vault.ssh.constants import CA_KEY_TYPE, MOUNT, ROLE, ROLE_SETTINGS


def converge_ssh_ca(v, token, on):
    """Purpose: bring OpenBao's SSH certificate authority to the setting (manual 1.6.11.9.2): on — the SSH engine, its
             CA key (made once, inside OpenBao) and the signing role; off — the role deleted, so nothing can be
             signed, while the engine and its CA key are kept (on again keeps the CA machines know).
    Inputs:  v — settings (bao_request's); token — a fabric-setup token; on — bool.
    Returns: {"on": bool, "public_key": the CA's public key line, or "" when the engine was never made}.
    Fails:   ValidationError from bao_call (OpenBao refusing or unreachable).
    Feeds:   vault/ssh/set_ssh_certificates (the console's toggle), setup/setup_openbao (the vault step)."""
    mounts = bao_call(v, token, "GET", "sys/mounts")
    mounted = f"{MOUNT}/" in mounts or f"{MOUNT}/" in (mounts.get("data") or {})
    if not on:
        if mounted:
            bao_call(v, token, "DELETE", f"{MOUNT}/roles/{ROLE}")
            status, data = bao_request(v, "GET", f"{MOUNT}/config/ca", token=token)
            return {"on": False, "public_key": (data.get("data") or {}).get("public_key", "").strip()
                    if status == 200 else ""}
        return {"on": False, "public_key": ""}
    if not mounted:
        bao_call(v, token, "POST", f"sys/mounts/{MOUNT}", {
            "type": "ssh", "description": "fabric: SSH user certificates for the fabric admins (1.6.11.9)"})
    status, data = bao_request(v, "GET", f"{MOUNT}/config/ca", token=token)
    key = (data.get("data") or {}).get("public_key", "").strip() if status == 200 else ""
    if not key:
        made = bao_call(v, token, "POST", f"{MOUNT}/config/ca", {"generate_signing_key": True, "key_type": CA_KEY_TYPE})
        key = (made.get("data") or {}).get("public_key", "").strip()
    bao_call(v, token, "POST", f"{MOUNT}/roles/{ROLE}", ROLE_SETTINGS)
    if not key:
        raise ValidationError("OpenBao made no SSH CA key")
    return {"on": True, "public_key": key}
