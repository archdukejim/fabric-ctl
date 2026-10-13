from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.directory.constants import ROLE_NAME_RE


def remove_role(v, actor, name, source="web"):
    """Purpose: Delete a device role, refused while any of this site's devices, or any reservation of its address
             plan (1.11.1.7), still names it (fabricRoleName) so no device silently loses (or keeps) access.
    Inputs:  v — fabric vars; actor — str, for the audit; name — ROLE_NAME_RE; source — default "web".
    Returns: None.
    Fails:   ValidationError "invalid role name: ..."; "role <name> still has <n> device(s); take them out
             first"; "role <name> is named by <n> reservation(s): <ip> (<name>), …"; "no such entry";
             run_op's errors (the directory unreachable, or refusing: e.g. another site's object).
    Feeds:   agent/ (fabric-agent) Handler.directory (POST /v1/roles/<name>/delete) -> webui agentclient.delete_role.
    Notes:   audited as ROLE_REMOVE.
    """
    if not ROLE_NAME_RE.match(str(name)):
        raise ValidationError(f"invalid role name: {name!r}")
    run_op(v, load_secrets(), "remove_role", {"name": name})
    write_audit(actor, "ROLE_REMOVE", f"role={name}", source)
