from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def create_ou(v, actor, parent, name, source="web", secrets=None, container="samba"):
    """Purpose: an admin's own OU (manual 1.6.12.7, Create OU; `ous:admin`, 1.6.12.11) under OU=people,
             OU=service-accounts, OU=groups, a machine type's OU, or an admin's own below them. OUs grant nothing
             (2.1.6.72), so no tier or grant decides who may add a folder: the permission alone.
    Inputs:  v — rendered vars; actor — str, for the audit; parent — the parent's path ("people", "machines/servers");
             name — the OU's name; source — audit source; secrets — fabric's secrets (default: load_secrets());
             container — the DC's container.
    Returns: {"path", "dn"}.
    Fails:   ValidationError "parent and name must be text"; the DC's: a bad name, one of fabric's folders' names, a
             parent that takes no admin's folders, no such parent, "that name is already taken" (an OU of that name
             there), "the directory refused the change …" (a folder fabric's agent may not write).
    Feeds:   agent route POST /v1/ous; domain/run_ou_command (create).
    Notes:   audited OU_CREATE."""
    if not isinstance(parent, str) or not isinstance(name, str):
        raise ValidationError("parent and name must be text")
    done = run_op(v, secrets if secrets is not None else load_secrets(), "create_ou",
                  {"parent": parent, "name": name}, container)
    write_audit(actor, "OU_CREATE", f"ou={done['path']}", source)
    return done
