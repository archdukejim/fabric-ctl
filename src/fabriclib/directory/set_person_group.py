from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.granted_from_above import granted_from_above
from fabriclib.directory.common.person_guard import person_guard
from fabriclib.directory.common.privileged_groups import privileged_groups
from fabriclib.directory.run_op import run_op
from fabriclib.keycloak.fabric_groups import fabric_groups
from fabriclib.secrets.load_secrets import load_secrets


def set_person_group(v, actor, group, uid, member, privileged=False, source="web", secrets=None, container="samba"):
    """Purpose: put a person in a group, or take them out (manual 1.6.3.16): the site's groups, and at the root site
             the organisation's (the directory's access control decides, 1.6.3.6). A fabric group (one carrying a
             role bundle) only with privileged; the admin group never loses its last member who can sign in.
    Inputs:  v — fabric vars (site_name, fabric_groups', webui_admin_group); actor — str, for the audit; group — the
             group's name; uid — the user name; member — bool: in (True) or out; privileged — bool: root, or
             system:admin; source — audit source; secrets — fabric's secrets (default: load_secrets()); container —
             the DC's container.
    Returns: {"uid", "group", "member", "changed"}.
    Fails:   ValidationError "<group> is granted only from a site above" (at a site with an upstream: its own admins,
             role and console role groups, before anything is asked); ValidationError "<group> carries fabric
             permissions: only an admin can change its members"; person_guard's
             (no such person; the last admin who can sign in); run_op's ("no such entry": no such group;
             "the directory refused the change …": a group this site may not change); load_secrets' errors.
    Feeds:   agent route POST /v1/people/<uid>/groups (people:groups); directory/run_people_command.
    Notes:   audited as PERSON_GROUP_ADD / PERSON_GROUP_REMOVE when it changed something. Keycloak reads the groups
             from the directory at the person's next sign-in."""
    if granted_from_above(v, group):
        raise ValidationError(f"{group} is granted only from a site above (2.1.9.21): there, fabricctl federation "
                              f"roles grant {v['site_name']} <role>, or the People page of a site above")
    secrets = secrets if secrets is not None else load_secrets()
    if group in fabric_groups(v) and not privileged:
        raise ValidationError(f"{group} carries fabric permissions: only an admin can change its members")
    admin_group = v.get("webui_admin_group") or "admins"
    person_guard(v, secrets, uid, True, "change their groups", last_admin=not member and group == admin_group,
                 container=container)
    if member:
        changed = run_op(v, secrets, "add_group_member", {"group": group, "uid": uid,       # placement: 2.1.9.24
                                                          "privileged": privileged_groups(v)}, container)["added"]
    else:
        changed = run_op(v, secrets, "remove_group_member", {"group": group, "uid": uid}, container)["removed"]
    if changed:
        write_audit(actor, "PERSON_GROUP_ADD" if member else "PERSON_GROUP_REMOVE", f"user={uid} group={group}",
                    source)
    return {"uid": uid, "group": group, "member": bool(member), "changed": changed}
