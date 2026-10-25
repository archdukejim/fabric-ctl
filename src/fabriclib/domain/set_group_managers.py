from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.constants import DIRECTORY_ADMINS
from fabriclib.directory.run_op import run_op
from fabriclib.keycloak.fabric_groups import fabric_groups
from fabriclib.secrets.load_secrets import load_secrets


def set_group_managers(v, actor, name, managers, add, remove, only_from="", caller=None, source="web", secrets=None,
                       container="samba"):
    """Purpose: a group's managers and their controls (manual 1.6.12.5, level 1 of 2.1.6.67; `groups:admin`): any
             person or group may be a manager, allowed to add, remove or both, and limited to adding people already in
             another group when set; after fabric-agent's check (the tier above the group: the Enterprise Admin for
             `directory-admins`, a Directory Administrator for the rest).
    Inputs:  v — rendered vars; actor — str, for the audit; name — the group; managers — list of user or group names
             (empty: none); add, remove — bool; only_from — a group's name or ""; caller — the signed-in person's user
             name, or None (root); source — audit source; secrets — fabric's secrets (default: load_secrets());
             container — the DC's container.
    Returns: {"name", "managers", "add", "remove", "only_from", "changed"}.
    Fails:   ValidationError: "managers: a list of at most 20 names"; check_access's; the DC's (a group that takes no
             managers, a manager that cannot be one, no such group).
    Feeds:   agent route POST /v1/groups/<name>/managers; domain/run_group_command (managers).
    Notes:   audited GROUP_MANAGERS when it changed something."""
    if not isinstance(managers, list) or len(managers) > 20 or not all(isinstance(m, str) for m in managers):
        raise ValidationError("managers: a list of at most 20 names")
    if not isinstance(only_from, str):
        raise ValidationError("only_from must be text")
    check_access(v, caller, "groups:admin", {"name": name}, container)
    done = run_op(v, secrets if secrets is not None else load_secrets(), "set_group_managers",
                  {"name": name, "managers": managers, "add": bool(add), "remove": bool(remove),
                   "only_from": only_from, "bundles": sorted(fabric_groups(v) - {DIRECTORY_ADMINS})}, container)
    if done["changed"]:
        write_audit(actor, "GROUP_MANAGERS", f"group={done['name']} managers={','.join(done['managers']) or '-'} "
                    f"add={done['add']} remove={done['remove']} only_from={done['only_from'] or '-'}", source)
    return done
