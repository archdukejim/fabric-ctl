import re

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.person_guard import person_guard
from fabriclib.directory.create_person import MAIL_RE
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets

DISPLAY_RE = re.compile(r"^[\w .,'()-]{1,64}$")


def edit_person(v, actor, uid, name=None, email=None, caller=None, source="web", secrets=None, container="samba"):
    """Purpose: a person's display name and e-mail address changed (manual 1.6.12.4, Edit; `people:edit`, 1.6.12.11):
             after fabric-agent's check (a grant's people edit reaching them, or the tier above them).
    Inputs:  v — rendered vars; actor — str, for the audit; uid — the user name; name — the display name (letters,
             digits and simple punctuation, 1-64) or None; email — an address with a dotted domain, or None; caller —
             the signed-in person's user name, or None (root); source — audit source; secrets — fabric's secrets
             (default: load_secrets()); container — the DC's container.
    Returns: {"uid", "name", "email", "changed": [attributes]}.
    Fails:   ValidationError "give a display name or an e-mail address", "display name: …", "e-mail address looks
             wrong", person_guard's (check_access's refusals; no such person), "that name is already taken" (the
             address is another's).
    Feeds:   agent route POST /v1/people/<uid>/edit; domain/run_person_command (edit).
    Notes:   audited PERSON_EDIT when something changed. Keycloak reads the new values at the next sign-in."""
    if name is None and email is None:
        raise ValidationError("give a display name or an e-mail address")
    if name is not None and not DISPLAY_RE.match(name):
        raise ValidationError("display name: letters, digits and simple punctuation, 1-64")
    if email is not None and not MAIL_RE.match(email):
        raise ValidationError("e-mail address looks wrong")
    secrets = secrets if secrets is not None else load_secrets()
    person_guard(v, secrets, uid, caller, "people:edit", "edit them", container=container)
    done = run_op(v, secrets, "edit_person", {"uid": uid, "name": name, "email": email}, container)
    if done["changed"]:
        write_audit(actor, "PERSON_EDIT", f"user={uid} changed={','.join(done['changed'])}", source)
    return done
