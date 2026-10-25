import urllib.parse

from fabriclib.common.errors import ValidationError
from fabriclib.keycloak.keycloak_admin import keycloak_admin


def end_other_sessions(v, secrets, uid, keep=None):
    """Purpose: end a person's Keycloak sessions but one (manual 1.8.6.6): after they change their own password, every
             single sign-on they hold elsewhere ends, and the session they changed it from stays.
    Inputs:  v — fabric vars (keycloak_admin's); secrets — fabric's secrets (keycloak_admin_user/password); uid — the
             user name; keep — the session to keep (the ID token's `sid`), or None (end them all).
    Returns: int, how many sessions were ended.
    Fails:   ValidationError "Keycloak refused: …"; OSError / ssl errors if Keycloak is unreachable.
    Feeds:   domain/change_own_password."""
    ended = 0
    try:
        kc, realm = keycloak_admin(v, secrets)
        r, u = urllib.parse.quote(realm, safe=""), urllib.parse.quote(uid, safe="")
        for user in kc.call("GET", f"/{r}/users?username={u}&exact=true")[1]:
            for s in kc.call("GET", f"/{r}/users/{user['id']}/sessions")[1]:
                if keep and s.get("id") == keep:
                    continue
                kc.call("DELETE", f"/{r}/sessions/{urllib.parse.quote(str(s['id']), safe='')}", allow=(404,))
                ended += 1
    except SystemExit as exc:                # the admin client's way of saying Keycloak refused
        raise ValidationError(f"Keycloak refused: {exc}")
    return ended
