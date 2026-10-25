from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def move_machine(v, actor, name, path, caller=None, source="web", secrets=None, container="samba"):
    """Purpose: a computer moved to another folder under OU=machines (manual 1.6.12.6, Move to folder; `ous:admin`
             with `machines:admin`, 1.6.12.11): its groups stay, so nobody's access changes (2.1.6.72); after
             fabric-agent's check (a grant's machines move reaching it, or a Directory Administrator).
    Inputs:  v — rendered vars; actor — str, for the audit; name — the host name; path — the target folder's path
             ("machines", "machines/servers/web"); caller — the signed-in person's user name, or None (root); source —
             audit source; secrets — fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"name", "path", "changed"}.
    Fails:   ValidationError "name and path must be text"; check_access's; the DC's (a folder not under OU=machines,
             no such folder, no such machine, a fabric host).
    Feeds:   agent route POST /v1/machines/<name>/move; domain/run_machine_command (move).
    Notes:   audited MACHINE_MOVE when it moved."""
    if not isinstance(name, str) or not isinstance(path, str):
        raise ValidationError("name and path must be text")
    check_access(v, caller, "machines:move", {"name": name}, container)
    done = run_op(v, secrets if secrets is not None else load_secrets(), "move_machine",
                  {"name": name, "path": path}, container)
    if done["changed"]:
        write_audit(actor, "MACHINE_MOVE", f"machine={name} ou={done['path']}", source)
    return done
