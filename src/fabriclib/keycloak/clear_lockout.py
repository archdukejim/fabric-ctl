import urllib.parse

from fabriclib.common.errors import ValidationError
from fabriclib.keycloak.keycloak_admin import keycloak_admin


def clear_lockout(v, secrets, uid):
    """Purpose: Keycloak's own brute-force lockout of a person cleared (the realm's login protection, ensure_realm), so
             an unlock (manual 1.6.3.18) lets them sign in at once, not after Keycloak's wait.
    Inputs:  v — fabric vars (keycloak_admin's); secrets — fabric's secrets (keycloak_admin_user/password); uid — the
             user name.
    Returns: int, how many Keycloak users were cleared (0 when Keycloak never saw them).
    Fails:   ValidationError "Keycloak refused: …"; OSError / ssl errors if Keycloak is unreachable.
    Feeds:   directory/unlock_person."""
    cleared = 0
    try:
        kc, realm = keycloak_admin(v, secrets)
        r, u = urllib.parse.quote(realm, safe=""), urllib.parse.quote(uid, safe="")
        for user in kc.call("GET", f"/{r}/users?username={u}&exact=true")[1]:
            kc.call("DELETE", f"/{r}/attack-detection/brute-force/users/{user['id']}")
            cleared += 1
    except SystemExit as exc:                # the admin client's way of saying Keycloak refused
        raise ValidationError(f"Keycloak refused: {exc}")
    return cleared
