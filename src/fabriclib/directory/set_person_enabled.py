from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.person_guard import person_guard
from fabriclib.directory.run_op import run_op
from fabriclib.keycloak.enable_person import enable_person
from fabriclib.keycloak.sign_out_person import sign_out_person
from fabriclib.secrets.load_secrets import load_secrets


def set_person_enabled(v, actor, uid, enabled, privileged=False, source="web", secrets=None, container="samba"):
    """Purpose: disable a person of this site, or enable them again (manual 1.6.3.16): disabling blocks every sign-in
             at once — the directory account is disabled (Keycloak, 802.1X, Windows and Linux logons refuse it) and
             their Keycloak sessions end; their account, groups and certificates stay.
    Inputs:  v — fabric vars (site_name, fabric_groups', keycloak_admin's); actor — str, for the
             audit and the self check; uid — the user name; enabled — bool; privileged — bool: root, or
             system:admin (a fabric-group member needs it); source — audit source; secrets — fabric's secrets
             (default: load_secrets()); container — the DC's container.
    Returns: {"uid", "enabled", "changed"}.
    Fails:   ValidationError from person_guard (no such person; a fabric-group member without privileged; yourself;
             the last admin who can sign in, when disabling) or run_op ("no such entry": another site's person);
             "Keycloak refused: …"; load_secrets' errors.
    Feeds:   agent route POST /v1/people/<uid>/disable|enable (people:disable); directory/run_people_command.
    Notes:   audited as PERSON_DISABLE / PERSON_ENABLE when it changed something. Sessions end before the account is
             disabled: Keycloak admits enabled people only, so after it no longer finds the person to sign them out
             (and refuses them a new sign-in or a refresh)."""
    secrets = secrets if secrets is not None else load_secrets()
    what = "enable them" if enabled else "disable them"
    person_guard(v, secrets, uid, privileged, what, actor=None if enabled else actor, last_admin=not enabled,
                 container=container)
    if not enabled:                           # first, as remove_person: once the directory account is disabled,
        sign_out_person(v, secrets, uid)      # Keycloak's filter (enabled people only, 2.1.6.83) no longer finds it
    done = run_op(v, secrets, "set_person", {"uid": uid, "enabled": bool(enabled)}, container)
    if enabled:
        enable_person(v, secrets, uid)        # Keycloak's copy, disabled by a sign-in tried meanwhile
    if done.get("changed"):
        write_audit(actor, "PERSON_ENABLE" if enabled else "PERSON_DISABLE", f"user={uid}", source)
    return done
