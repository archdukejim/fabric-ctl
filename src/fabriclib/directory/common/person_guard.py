from fabriclib.common.errors import ValidationError
from fabriclib.directory.common.site_helpdesk_refusal import site_helpdesk_refusal
from fabriclib.directory.run_op import run_op
from fabriclib.keycloak.fabric_groups import fabric_groups


def _other_admins(v, secrets, uid, container):
    """Purpose: the admin group's members, other than uid, who can still sign in.
    Inputs:  v — fabric vars (webui_admin_group); secrets — fabric's secrets; uid — the person left out; container —
             the DC's container.
    Returns: list of str user names.
    Fails:   ValidationError from run_op.
    Feeds:   person_guard."""
    group = v.get("webui_admin_group") or "admins"
    people = run_op(v, secrets, "list_people", container=container)["users"]
    return [p["uid"] for p in people if group in p["groups"] and p["uid"] != uid and not p["locked"]]


def person_guard(v, secrets, uid, privileged, what, actor=None, last_admin=False, container="samba", own_site=False):
    """Purpose: who may change a person's sign-in (manual 1.6.3.8, 1.6.3.16): a member of a fabric group only an admin
             (or root) — otherwise the helpdesk could take over, or lock out, an admin; never yourself, for what
             would sign you out for good; never the last admin who can still sign in; and, for the site helpdesk
             (own_site, 2.1.9.21), only a person of this site's own OU=people who holds no role.
    Inputs:  v — fabric vars (fabric_groups', webui_admin_group); secrets — fabric's secrets; uid — the person;
             privileged — bool: root, or system:admin; what — str, the change for the message ("disable them");
             actor — the caller's user name, refused when it is uid (None: no such check); last_admin — bool,
             refuse when uid is the admin group's last member who can sign in; container — the DC's container;
             own_site — bool, the caller holds the permission only as the site helpdesk (site:people:*).
    Returns: the person: {"uid", "dn", "groups"}.
    Fails:   ValidationError "no such entry" (no such person, or a service account); "<uid> is in a fabric group (…):
             only an admin can <what>"; "you cannot <what> yourself"; "<uid> is the last admin who can sign in: add
             another admin first"; site_helpdesk_refusal's (another site's person, a person who holds a role); run_op's
             other refusals.
    Feeds:   reset_sign_in, set_person_enabled, remove_person, set_person_group."""
    person = run_op(v, secrets, "get_person", {"uid": uid}, container)
    refusal = site_helpdesk_refusal(v, person, what) if own_site else ""
    if refusal:
        raise ValidationError(refusal)
    held = sorted(set(person["groups"]) & fabric_groups(v))
    if held and not privileged:
        raise ValidationError(f"{uid} is in a fabric group ({', '.join(held)}): only an admin can {what}")
    if actor is not None and actor == uid:
        raise ValidationError(f"you cannot {what} yourself")
    admin_group = v.get("webui_admin_group") or "admins"
    if last_admin and admin_group in person["groups"] and not _other_admins(v, secrets, uid, container):
        raise ValidationError(f"{uid} is the last admin who can sign in: add another admin first")
    return person
