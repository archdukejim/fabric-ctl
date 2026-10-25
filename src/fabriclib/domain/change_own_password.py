import json
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.keycloak.end_other_sessions import end_other_sessions
from fabriclib.secrets.load_secrets import load_secrets


def change_own_password(v, uid, current, new, keep_session=None, secrets=None, container="samba"):
    """Purpose: a person changes their own password (manual 1.8.6.6, 2.1.8.11; 2.1.1.62: through fabric-agent to the
             DC, no longer Keycloak's account page): with their current password, written to AD at once as the person
             (the DC checks it and the domain's policy), never pending; then their sessions elsewhere end.
    Inputs:  v — rendered vars (keycloak_admin's); uid — the signed-in person (the agent's token: never from the
             request); current — their current password; new — the new one; keep_session — the token's session
             (`sid`), kept; secrets — fabric's secrets (default: load_secrets(); Keycloak's admin); container — the DC's
             container.
    Returns: {"uid", "changed": True, "sessions_ended": int}.
    Fails:   ValidationError "a person's own password: sign in as them" (root, no person), "current and new passwords
             must be text", "the new password is the current one", "the current password is wrong, or the account may
             not sign in …", "the domain's password policy refused the new password …", "the domain controller is not
             running"; Keycloak's ("Keycloak refused: …": the password is changed by then, and said so).
    Feeds:   agent route POST /v1/account/password (any signed-in person).
    Notes:   audited PASSWORD_CHANGE_OWN (never a password); a refused change is not audited, as a failed sign-in is
             not. Both passwords go to the DC on stdin only."""
    if not uid:
        raise ValidationError("a person's own password: sign in as them")
    if not isinstance(current, str) or not isinstance(new, str) or not current or not new:
        raise ValidationError("current and new passwords must be text")
    if len(new) > 256:
        raise ValidationError("the new password is longer than 256 characters")
    if new == current:
        raise ValidationError("the new password is the current one")
    res = subprocess.run(["docker", "exec", "-i", "-e", "PYTHONDONTWRITEBYTECODE=1", container, "python3",
                          "/fabric/change_own_password.py"],
                         input=json.dumps({"uid": uid, "current": current, "new": new}), capture_output=True,
                         text=True, timeout=60)
    if res.returncode != 0 or not res.stdout.strip():
        raise ValidationError("the domain controller is not running")
    answer = json.loads(res.stdout.strip().splitlines()[-1])
    if "error" in answer:
        raise ValidationError(answer["error"])
    write_audit(uid, "PASSWORD_CHANGE_OWN", f"user={uid}", "web")
    try:
        ended = end_other_sessions(v, secrets if secrets is not None else load_secrets(), uid, keep_session)
    except ValidationError as e:
        raise ValidationError(f"your password is changed, but your other sessions could not be ended: {e}")
    return {"uid": uid, "changed": True, "sessions_ended": ended}
