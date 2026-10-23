from fabriclib.common.errors import ValidationError
from fabriclib.localadmin.common.bao_call import bao_call
from fabriclib.localadmin.constants import MOUNT
from fabriclib.localadmin.secret_path import secret_path
from fabriclib.vault.common.bao_request import bao_request


def read_local_admin_secret(v, token, password=False):
    """Purpose: what OpenBao holds for the fabric host's local-admin (manual 1.7.1.4.2): the current version (the path's
             metadata `current`), its policy and when it was set; with password, the current version's password (a
             read OpenBao's audit log records: a check-out's).
    Inputs:  v — vars; token — a fabric-setup token; password — bool.
    Returns: {"current": int or None (nothing marked current yet), "policy", "set_on", "reason", "versions": int,
             and "password" when asked}.
    Fails:   ValidationError when OpenBao refuses or does not answer, or (password) when no version is current.
    Feeds:   checkout_local_admin, local_admin_checks (doctor), setup/setup_local_admin."""
    path = secret_path(v)
    status, data = bao_request(v, "GET", f"{MOUNT}/metadata/{path}", token=token)
    if status == 404:
        meta = {}
    elif status == 200:
        meta = data.get("data") or {}
    else:
        raise ValidationError(f"OpenBao GET {MOUNT}/metadata/{path}: {data.get('errors') or status}")
    custom = meta.get("custom_metadata") or {}
    current = int(custom["current"]) if str(custom.get("current") or "").isdigit() else None
    out = {"current": current, "policy": custom.get("policy"), "set_on": custom.get("set_on"),
           "reason": custom.get("reason"), "versions": len(meta.get("versions") or {})}
    if password:
        if current is None:
            raise ValidationError("OpenBao holds no current password for local-admin: run `sudo fabricctl setup "
                                  "--step localadmin`")
        out["password"] = bao_call(v, token, "GET", f"{MOUNT}/data/{path}?version={current}")["data"]["data"][
            "password"]
    return out
