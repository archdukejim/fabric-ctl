from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.person_guard import person_guard
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def unlock_person(v, actor, uid, caller=None, source="web", secrets=None, container="samba"):
    """Purpose: a locked-out person unlocked (manual 1.6.12.4, Unlock; `people:reset` widened, 1.6.12.11): their
             lockout cleared in AD, their password kept; after fabric-agent's check (a grant's people unlock reaching
             them, or the tier above them).
    Inputs:  v — rendered vars; actor — str, for the audit; uid — the user name; caller — the signed-in person's user
             name, or None (root); source — audit source; secrets — fabric's secrets (default: load_secrets());
             container — the DC's container.
    Returns: {"uid", "changed": bool} (False: they were not locked out).
    Fails:   ValidationError from person_guard (check_access's refusals; no such person) or run_op.
    Feeds:   agent route POST /v1/people/<uid>/unlock; domain/run_person_command (unlock).
    Notes:   audited PERSON_UNLOCK when it changed something."""
    secrets = secrets if secrets is not None else load_secrets()
    person_guard(v, secrets, uid, caller, "people:unlock", "unlock them", container=container)
    done = run_op(v, secrets, "unlock_person", {"uid": uid}, container)
    if done["changed"]:
        write_audit(actor, "PERSON_UNLOCK", f"user={uid}", source)
    return done
