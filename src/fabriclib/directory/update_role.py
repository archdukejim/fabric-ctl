from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.check_role_fields import check_role_fields
from fabriclib.directory.common.check_role_vlan import check_role_vlan
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.directory.constants import ROLE_NAME_RE


def update_role(v, actor, name, fields, source="web", plan=None):
    """Purpose: Replace a device role's description, permissions, VLAN and priority; members are managed
             from each device.
    Inputs:  v — fabric vars; actor — str, for the audit; name — ROLE_NAME_RE; fields — as add_role
             (check_role_fields); source — default "web";
             plan — this site's address plan (tests), default read by check_role_vlan.
    Returns: None.
    Fails:   check_role_vlan's (a VLAN not in this site's address plan, 1.11.1.8);
             ValidationError "invalid role name: ..."; check_role_fields' messages; "no such entry" (no
             such role);
             run_op's errors (the directory unreachable, or refusing: e.g. another site's object).
    Feeds:   agent/ (fabric-agent) Handler.directory (POST /v1/roles/<name>) -> webui agentclient.save_role.
    Notes:   audited as ROLE_UPDATE.
    """
    if not ROLE_NAME_RE.match(str(name)):
        raise ValidationError(f"invalid role name: {name!r}")
    f = check_role_fields(fields)
    secrets = load_secrets()
    check_role_vlan(v, f["vlan"], plan, secrets)
    run_op(v, secrets, "save_role", {"name": name, **f, "new": False})
    write_audit(actor, "ROLE_UPDATE", f"role={name} permissions={','.join(f['permissions']) or '-'} "
                                      f"vlan={f['vlan'] or '-'} priority={f['priority']}", source)
