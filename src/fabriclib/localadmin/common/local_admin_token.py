from fabriclib.common.errors import ValidationError
from fabriclib.vault.common.approle_login import approle_login
from fabriclib.vault.common.bao_request import bao_request
from fabriclib.vault.constants import SETUP_CREDS


def local_admin_token(v, login=approle_login):
    """Purpose: a fabric-setup token for the local admin passwords (manual 1.7.1.4), or why OpenBao cannot give one now:
             unreachable, sealed or not initialised (a rotation then waits, 2.1.7.20; a check-out is refused).
    Inputs:  v — vars (OpenBao's address, openbao_key_dir); login — approle_login (tests give their own).
    Returns: (token str, None), or (None, why str).
    Fails:   never for OpenBao's state (it is the answer); OSError reading the credentials propagates.
    Feeds:   check_local_admin, checkout_local_admin, set_local_admin_policy, local_admin_checks, remove_local_admin,
             setup/setup_local_admin."""
    try:
        status, data = bao_request(v, "GET", "sys/health")
    except ValidationError as e:
        return None, f"OpenBao does not answer ({e})"
    if status == 503 or data.get("sealed"):
        return None, "OpenBao is sealed (locked)"
    if status == 501 or data.get("initialized") is False:
        return None, "OpenBao is not initialised"
    try:
        return login(v, SETUP_CREDS), None
    except ValidationError as e:
        return None, str(e)
