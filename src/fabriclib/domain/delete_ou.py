from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def delete_ou(v, actor, path, source="web", secrets=None, container="samba"):
    """Purpose: an admin's own OU deleted (manual 1.6.12.7, Delete; `ous:admin`), refused while it holds anything,
             naming what; fabric's OUs refused.
    Inputs:  v — rendered vars; actor — str, for the audit; path — the OU's path; source — audit source; secrets —
             fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"path"}.
    Fails:   ValidationError "ou must be text"; the DC's: fabric's own OU, no such OU, "<path> is not empty: it holds
             …".
    Feeds:   agent route POST /v1/ous/delete; domain/run_ou_command (delete).
    Notes:   audited OU_REMOVE."""
    if not isinstance(path, str):
        raise ValidationError("ou must be text")
    done = run_op(v, secrets if secrets is not None else load_secrets(), "delete_ou", {"path": path}, container)
    write_audit(actor, "OU_REMOVE", f"ou={done['path']}", source)
    return done
