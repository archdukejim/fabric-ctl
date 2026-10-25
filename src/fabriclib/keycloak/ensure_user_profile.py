from fabriclib.keycloak.quote import q
from fabriclib.keycloak.step import step


def ensure_user_profile(kc, realm):
    """Purpose: the realm's user profile takes a person without an e-mail address (2.1.6.93): AD keeps it optional,
             while Keycloak's own default requires one of every user and asks for it at sign-in (its verify-profile
             page). The requirement is lifted; a value given is still checked as an address, and the other
             attributes are left as Keycloak has them.
    Inputs:  kc — Admin; realm — realm name.
    Returns: bool, True when the profile was changed.
    Fails:   SystemExit from Admin.call.
    Feeds:   configure_keycloak (after ensure_realm)."""
    profile = kc.call("GET", f"/{q(realm)}/users/profile")[1]
    changed = False
    for attr in profile.get("attributes", []):
        if attr.get("name") == "email" and attr.get("required"):
            del attr["required"]
            changed = True
    if changed:
        kc.call("PUT", f"/{q(realm)}/users/profile", profile)
        step("user profile: an e-mail address is optional (2.1.6.93)")
    return changed
