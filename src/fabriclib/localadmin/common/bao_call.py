from fabriclib.common.errors import ValidationError
from fabriclib.vault.common.bao_request import bao_request


def bao_call(v, token, method, path, body=None):
    """Purpose: one OpenBao call that must succeed (the local admin passwords' calls, manual 1.7.1.4.2).
    Inputs:  v — vars (OpenBao's address); token — a fabric-setup token; method, path, body — as bao_request.
    Returns: the answer's data (dict; {} for an empty answer).
    Fails:   ValidationError with OpenBao's errors, or "OpenBao is not reachable" from bao_request.
    Feeds:   ensure_local_admin_store, set_local_admin_password, read_local_admin_secret, remove_local_admin."""
    status, data = bao_request(v, method, path, token=token, body=body)
    if status not in (200, 204):
        raise ValidationError(f"OpenBao {method} {path}: {data.get('errors') or status}")
    return data
