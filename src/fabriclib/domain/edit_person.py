from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.person_guard import person_guard
from fabriclib.directory.run_op import run_op
from fabriclib.domain.person_fields import read_person_fields
from fabriclib.secrets.load_secrets import load_secrets


def edit_person(v, actor, uid, fields, caller=None, source="web", secrets=None, container="samba"):
    """Purpose: a person's details changed (manual 1.6.12.4, Edit; `people:edit`, 1.6.12.11; 2.1.6.93): AD's standard
             attributes, their names, contact, organisation, place, manager and employee ID, after fabric-agent's
             check (a grant's people edit reaching them, or the tier above them).
    Inputs:  v — rendered vars; actor — str, for the audit; uid — the user name; fields — {field: str}, the fields
             of person_fields.FIELDS to change (an empty value clears one); caller — the signed-in person's user
             name, or None (root); source — audit source; secrets — fabric's secrets (default: load_secrets());
             container — the DC's container.
    Returns: {"uid", "name", "email", "changed": [attributes], "person": {field: value}}.
    Fails:   ValidationError: read_person_fields' refusals, person_guard's (check_access's refusals; no such
             person), "that name is already taken" (the address is another's), "no person <manager>" (the manager
             is not a person).
    Feeds:   agent route POST /v1/people/<uid>/edit; domain/run_person_command (edit).
    Notes:   audited PERSON_EDIT when something changed. Keycloak reads the new values at the next sign-in."""
    fields = read_person_fields(uid, fields)
    secrets = secrets if secrets is not None else load_secrets()
    person_guard(v, secrets, uid, caller, "people:edit", "edit them", container=container)
    done = run_op(v, secrets, "edit_person", {"uid": uid, "fields": fields}, container)
    if done["changed"]:
        write_audit(actor, "PERSON_EDIT", f"user={uid} changed={','.join(done['changed'])}", source)
    return done
