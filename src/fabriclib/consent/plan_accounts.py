import grp
import pwd

from fabriclib.setup.common.service_account_name import service_account_name
from fabriclib.setup.errors import SetupError


def _uid_owner(uid):
    """Purpose: the user name that has a uid, or None.
    Inputs: uid — int.
    Returns: str or None.
    Fails: never.
    Feeds:   plan_accounts."""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def _gid_owner(gid):
    """Purpose: the group name that has a gid, or None.
    Inputs: gid — int.
    Returns: str or None.
    Fails: never.
    Feeds:   plan_accounts."""
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return None


def _user_uid(name):
    """Purpose: a user's uid, or None.
    Inputs: name — str.
    Returns: int or None.
    Fails: never.
    Feeds: plan_accounts."""
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


def _group_gid(name):
    """Purpose: a group's gid, or None.
    Inputs: name — str.
    Returns: int or None.
    Fails: never.
    Feeds: plan_accounts."""
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


def plan_accounts(v):
    """Purpose: the service accounts setup creates (manual 1.2.9.3 `accounts`, 1.2.9.8): one fabric-* user and group
             per service_users entry, in fabric's uid band.
    Inputs:  v — vars: service_users {key: {uid, gid[, name]}} (uid 0 entries are skipped; gid 0 — Keycloak's
             image convention — has no group of its own).
    Returns: list of actions in order, each {"text": what the question shows, "do": "group"|"user",
             + its fields}: groups and users to create. [] when everything is in place.
    Fails:   SetupError when an id is taken by another account or a name has another id (the message names both:
             fabric never takes over someone else's account).
    Feeds:   consent/plan_host_changes (the question), setup/create_accounts (the step does exactly these)."""
    actions = []
    for key, ids in (v.get("service_users") or {}).items():
        uid, gid = int(ids["uid"]), int(ids["gid"])
        if uid == 0:
            continue
        name = service_account_name(key, ids)
        if gid:
            holder, has = _gid_owner(gid), _group_gid(name)
            if holder not in (None, name) or (has is not None and has != gid):
                raise SetupError(f"group id {gid} for {name} is taken by '{holder}' (or {name} has gid {has}): "
                                 f"choose another id with service_users.{key}.gid")
            if holder is None:
                actions.append({"do": "group", "name": name, "gid": gid, "text": f"create group {name} (gid {gid})"})
        holder, has = _uid_owner(uid), _user_uid(name)
        if holder not in (None, name) or (has is not None and has != uid):
            raise SetupError(f"user id {uid} for {name} is taken by '{holder}' (or {name} has uid {has}): "
                             f"choose another id with service_users.{key}.uid")
        if holder is None:
            actions.append({"do": "user", "name": name, "uid": uid, "gid": gid,
                            "text": f"create user {name} (uid {uid}, gid {gid}; no login, no home)"})
    return actions
