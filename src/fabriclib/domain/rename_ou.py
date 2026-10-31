from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def rename_ou(v, actor, path, name, source="web", secrets=None, container="samba"):
    """Purpose: an admin's own OU renamed (manual 1.6.12.7, Rename; `ous:admin`); what it holds moves with it, and
             nobody's access changes (OUs grant nothing, 2.1.6.72). fabric's OUs are refused.
    Inputs:  v — rendered vars; actor — str, for the audit; path — the OU's path; name — its new name; source — audit
             source; secrets — fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"path", "dn"} (the new ones).
    Fails:   ValidationError "ou and name must be text"; the DC's: a bad name, fabric's own OU, no such OU, "that name
             is already taken".
    Feeds:   agent route POST /v1/ous/rename; domain/run_ou_command (rename).
    Notes:   audited OU_RENAME."""
    if not isinstance(path, str) or not isinstance(name, str):
        raise ValidationError("ou and name must be text")
    done = run_op(v, secrets if secrets is not None else load_secrets(), "rename_ou",
                  {"path": path, "name": name}, container)
    write_audit(actor, "OU_RENAME", f"ou={path} now={done['path']}", source)
    return done
