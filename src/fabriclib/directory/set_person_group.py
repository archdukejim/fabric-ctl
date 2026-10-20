from fabriclib.access.check_access import check_access
from fabriclib.common.write_audit import write_audit
from fabriclib.grants.sync_grants import sync_grants
from fabriclib.directory.constants import DIRECTORY_ADMINS
from fabriclib.directory.common.person_guard import _other_admins
from fabriclib.common.errors import ValidationError
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def set_person_group(v, actor, group, uid, member, caller=None, source="web", secrets=None, container="samba"):
    """Purpose: put a person in a group, or take them out (manual 1.6.3.16, 1.6.12.5): a group's members, level 2 of
             2.1.6.67, changed by the tier above the group or by its managers within their controls (fabric-agent's
             check, check_access "groups:members"); never AD's own groups, the grants' computed groups or those fabric
             fills. The admin group never loses its last member who can sign in.
    Inputs:  v — fabric vars (site_name, fabric_groups'); actor — str, for the audit; group — the group's name; uid —
             the user name, or a group's name (a nested group); member — bool: in (True) or out; caller — the
             signed-in person's user name, or None (root, acting for the Enterprise Admin); source — audit source;
             secrets — fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"uid", "group", "member", "changed"}.
    Fails:   ValidationError from check_access (why: not a manager, the controls, the tier, the kind of group, no such
             person or group); "<uid> is the last admin who can sign in: add another admin first"; run_op's;
             load_secrets' errors.
    Feeds:   agent routes POST /v1/people/<uid>/groups (people:groups) and /v1/groups/<name>/members (any signed-in
             person: the managers need no permission, 1.6.12.11); directory/run_people_command;
             domain/run_group_command.
    Notes:   audited as PERSON_GROUP_ADD / PERSON_GROUP_REMOVE when it changed something (with the access it was
             allowed by). Keycloak reads the groups from the directory at the person's next sign-in."""
    secrets = secrets if secrets is not None else load_secrets()
    access = check_access(v, caller, "groups:members", {"name": group, "member": uid, "add": bool(member)}, container)
    if not member and group == DIRECTORY_ADMINS and not _other_admins(v, secrets, uid, container):
        raise ValidationError(f"{uid} is the last admin who can sign in: add another admin first")
    if member:
        changed = run_op(v, secrets, "add_group_member", {"group": group, "uid": uid}, container)["added"]
    else:
        changed = run_op(v, secrets, "remove_group_member", {"group": group, "uid": uid}, container)["removed"]
    if changed:
        write_audit(actor, "PERSON_GROUP_ADD" if member else "PERSON_GROUP_REMOVE",
                    f"user={uid} group={group} by={access['by']}", source)
        sync_grants(v, actor, source, container, quiet=True)  # the grants on that group follow at once (1.6.13.4)
    return {"uid": uid, "group": group, "member": bool(member), "changed": changed}
