from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.check_role_fields import check_role_fields
from fabriclib.directory.common.check_role_vlan import check_role_vlan
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.directory.constants import ROLE_NAME_RE


def add_role(v, actor, name, fields, source="web", plan=None):
    """Purpose: Create a device role: the permissions it grants its member devices, an optional VLAN and a
             priority (the lower number wins when roles set different VLANs).
    Inputs:  v — fabric vars; actor — str, for the audit; name — stripped, lower-cased, ROLE_NAME_RE;
             fields — {permissions, vlan, priority, description} (check_role_fields); source — default "web";
             plan — this site's address plan (tests), default read by check_role_vlan.
    Returns: the normalised role name.
    Fails:   check_role_vlan's (a VLAN not in this site's address plan, 1.11.1.8);
             ValidationError "role name: lowercase letters, digits, '-' and '_'"; check_role_fields'
             messages; "that name is already taken";
             run_op's errors (the directory unreachable, or refusing: e.g. another site's object).
    Feeds:   agent/ (fabric-agent) Handler.directory (POST /v1/roles) -> webui agentclient.save_role.
    Notes:   audited as ROLE_ADD.
    """
    name = str(name).strip().lower()
    if not ROLE_NAME_RE.match(name):
        raise ValidationError("role name: lowercase letters, digits, '-' and '_'")
    f = check_role_fields(fields)
    secrets = load_secrets()
    check_role_vlan(v, f["vlan"], plan, secrets)
    run_op(v, secrets, "save_role", {"name": name, **f, "new": True})
    write_audit(actor, "ROLE_ADD", f"role={name} permissions={','.join(f['permissions']) or '-'} "
                                   f"vlan={f['vlan'] or '-'} priority={f['priority']}", source)
    return name
