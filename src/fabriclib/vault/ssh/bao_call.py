from fabriclib.common.errors import ValidationError
from fabriclib.vault.common.bao_request import bao_request


def bao_call(v, token, method, path, body=None, ok=(200, 204)):
    """Purpose: one OpenBao call of the SSH engines that must succeed; a refusal of fabric-setup's policy says how to
             fix it (manual 1.6.11.9.2, 1.6.11.9.6).
    Inputs:  v — settings; token — a fabric-setup token; method, path, body — bao_request's; ok — success statuses.
    Returns: the response data (dict).
    Fails:   ValidationError: 403 (setup's policy predates SSH certificates or host certificates: run the vault step),
             or any other status with OpenBao's errors; from bao_request when OpenBao is unreachable.
    Feeds:   vault/ssh/converge_ssh_ca, vault/ssh/converge_ssh_host_ca."""
    status, data = bao_request(v, method, path, token=token, body=body)
    if status == 403:
        raise ValidationError("OpenBao refused fabric's setup role for SSH certificates: run `sudo fabricctl setup "
                              "--step vault` once (it gives the role the SSH engines), then try again")
    if status not in ok:
        raise ValidationError(f"OpenBao {method} {path}: {data.get('errors') or status}")
    return data
