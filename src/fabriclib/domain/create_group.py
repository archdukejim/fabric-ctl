from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.domain.group_name_refused import group_name_refused
from fabriclib.secrets.load_secrets import load_secrets


def create_group(v, actor, name, description="", caller=None, source="web", secrets=None, container="samba"):
    """Purpose: an admin's own group made in OU=groups (manual 1.6.12.5, Create group; `groups:admin`, the Directory
             Administrators, 1.6.12.11), after fabric-agent's check (the caller a Directory Administrator).
    Inputs:  v — rendered vars; actor — str, for the audit; name — the group's name (group_name_refused's rule);
             description — text (at most 200) or ""; caller — the signed-in person's user name, or None (root); source
             — audit source; secrets — fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"name", "gid"}.
    Fails:   ValidationError: group_name_refused's why; "description: …"; check_access's ("only a Directory
             Administrator may do this"); "that name is already taken" (any account or group of the domain).
    Feeds:   agent route POST /v1/groups; domain/run_group_command (create).
    Notes:   audited GROUP_CREATE."""
    why = group_name_refused(name)
    if why:
        raise ValidationError(why)
    if not isinstance(description, str) or len(description) > 200 or any(ord(c) < 32 for c in description):
        raise ValidationError("description: text on one line, at most 200 characters")
    check_access(v, caller, "groups:admin", {}, container)
    done = run_op(v, secrets if secrets is not None else load_secrets(), "create_group",
                  {"name": name, "description": description}, container)
    write_audit(actor, "GROUP_CREATE", f"group={name} gid={done['gid']}", source)
    return done
