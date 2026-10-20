from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.directory.constants import DIRECTORY_ADMINS
from fabriclib.directory.run_op import run_op


def _other_admins(v, secrets, uid, container):
    """Purpose: the admin group's members (directory-admins), other than uid, who can still sign in.
    Inputs:  v — fabric vars; secrets — fabric's secrets; uid — the person left out; container —
             the DC's container.
    Returns: list of str user names.
    Fails:   ValidationError from run_op.
    Feeds:   person_guard."""
    group = DIRECTORY_ADMINS
    people = run_op(v, secrets, "list_people", container=container)["users"]
    return [p["uid"] for p in people if group in p["groups"] and p["uid"] != uid and not p["locked"]]


def person_guard(v, secrets, uid, caller, action, what, actor=None, last_admin=False, container="samba"):
    """Purpose: who may change a person (manual 1.6.3.16, 1.6.12.2): fabric-agent's check first (check_access: the
             tiers, the grants' people rights, a fabric group's members only by a Directory Administrator, AD's top tier
             and fabric's own accounts by nobody); then never yourself, for what would sign you out for good; and never
             the last admin who can still sign in.
    Inputs:  v — fabric vars; secrets — fabric's secrets; uid — the person; caller — the signed-in person's user name,
             or None (root); action — check_access's ("people:reset", "people:disable", ...); what — str, the change
             for the message ("disable them"); actor — the caller's user name, refused when it is uid (None: no such
             check); last_admin — bool, refuse when uid is the admin group's last member who can sign in; container —
             the DC's container.
    Returns: the person: {"uid", "dn", "groups"}.
    Fails:   ValidationError from check_access (why it is refused); "no such entry" (no such person, or a service
             account); "you cannot <what> yourself"; "<uid> is the last admin who can sign in: add another admin
             first"; run_op's other refusals.
    Feeds:   reset_sign_in, set_person_enabled, remove_person, domain/edit_person, domain/unlock_person."""
    check_access(v, caller, action, {"name": uid}, container)
    person = run_op(v, secrets, "get_person", {"uid": uid}, container)
    if actor is not None and actor == uid:
        raise ValidationError(f"you cannot {what} yourself")
    if last_admin and DIRECTORY_ADMINS in person["groups"] and not _other_admins(v, secrets, uid, container):
        raise ValidationError(f"{uid} is the last admin who can sign in: add another admin first")
    return person
