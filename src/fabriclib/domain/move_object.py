from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.constants import DIRECTORY_ADMINS
from fabriclib.directory.run_op import run_op
from fabriclib.domain.move_machine import move_machine
from fabriclib.keycloak.fabric_groups import fabric_groups
from fabriclib.secrets.load_secrets import load_secrets

# who may move each kind, by fabric-agent's check (1.8.8.5, 1.8.8.9.4): whoever may edit the person, the tier above
# the group (its scope's), and a machine's move as before (move_machine: a grant's machines move)
CHECKS = {"person": ("people:edit", "PERSON_MOVE"), "group": ("groups:admin", "GROUP_MOVE")}


def move_object(v, actor, kind, name, path, caller=None, source="web", secrets=None, container="samba"):
    """Purpose: Move to... (manual 1.8.8.4, 1.8.8.5; decision 2.1.8.37): a person, group or computer moved to another
             OU, after fabric-agent's check; where it may go is the DC's (may_hold: for now each kind inside its own
             folder's tree, 2.3.8.6), and fabric's own objects stay put (2.1.6.100). Its groups stay, so nothing it may
             do changes (2.1.6.72). A computer goes through move_machine (its check and audit as before).
    Inputs:  v — rendered vars; actor — str, for the audit; kind — "person", "group" or "machine"; name — its user,
             group or host name; path — the target OU's path; caller — the signed-in person's user name, or None
             (root); source — audit source; secrets — fabric's secrets (default: load_secrets()); container — the DC's
             container.
    Returns: {"kind", "name", "path", "changed"}.
    Fails:   ValidationError: an unknown kind, name and path not text; check_access's; the DC's (where it may not go,
             no such OU or object, one of fabric's own).
    Feeds:   agent routes POST /v1/people/<uid>/move, /v1/groups/<name>/move.
    Notes:   audited PERSON_MOVE or GROUP_MOVE when it moved (MACHINE_MOVE by move_machine)."""
    if kind == "machine":
        return {"kind": kind, **move_machine(v, actor, name, path, caller=caller, source=source, secrets=secrets,
                                             container=container)}
    if kind not in CHECKS:
        raise ValidationError(f"kind: person, group or machine, not {kind!r}")
    if not isinstance(name, str) or not isinstance(path, str) or not name or not path:
        raise ValidationError("name and path: text, both given")
    action, event = CHECKS[kind]
    check_access(v, caller, action, {"name": name}, container)
    done = run_op(v, secrets if secrets is not None else load_secrets(), "move_object",
                  {"kind": kind, "name": name, "path": path,
                   "bundles": sorted(fabric_groups(v) - {DIRECTORY_ADMINS})}, container)
    if done["changed"]:
        write_audit(actor, event, f"{kind}={name} ou={done['path']}", source)
    return done
