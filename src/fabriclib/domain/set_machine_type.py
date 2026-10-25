from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.constants import MACHINE_TYPES
from fabriclib.directory.run_op import run_op
from fabriclib.grants.sync_grants import sync_grants
from fabriclib.secrets.load_secrets import load_secrets


def set_machine_type(v, actor, name, type, move=False, caller=None, source="web", secrets=None, container="samba"):
    """Purpose: a computer's type changed (manual 1.6.12.6, Change type; `machines:admin`): its type group, and so the
             grants on its type, at once (compiled); with move also its folder, to that type's OU. After fabric-agent's
             check: a grant's machines groups reaching it (and machines move, to move it), or a Directory
             Administrator.
    Inputs:  v — rendered vars; actor — str, for the audit; name — the host name; type — server, desktop or network;
             move — bool; caller — the signed-in person's user name, or None (root); source — audit source; secrets —
             fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"name", "type", "changed": [what], "kept_folder": an admin's folder kept (not moved), or ""}.
    Fails:   ValidationError "type: …"; check_access's; the DC's (no such machine, a fabric host).
    Feeds:   agent route POST /v1/machines/<name>/type; domain/run_machine_command (type).
    Notes:   audited MACHINE_TYPE when it changed something."""
    if type not in MACHINE_TYPES:
        raise ValidationError(f"type: one of {', '.join(MACHINE_TYPES)}")
    check_access(v, caller, "machines:groups", {"name": name}, container)
    if move:
        check_access(v, caller, "machines:move", {"name": name}, container)
    done = run_op(v, secrets if secrets is not None else load_secrets(), "set_machine_type",
                  {"name": name, "type": type, "move": bool(move)}, container)
    if done["changed"]:
        write_audit(actor, "MACHINE_TYPE", f"machine={name} type={type} {'; '.join(done['changed'])}", source)
        sync_grants(v, actor, source, container, quiet=True)   # the grants on its type follow at once (1.6.13.4)
    return done
