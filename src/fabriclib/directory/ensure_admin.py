from fabriclib.common.errors import ValidationError
from fabriclib.directory.constants import DIRECTORY_ADMINS
from fabriclib.directory.people_password import people_password
from fabriclib.directory.run_op import run_op


def ensure_admin(v, secrets, user, email, password=None, container="samba", full_name=None):
    """Purpose: the first Directory Administrator in the directory (manual 1.6.12.2; 2.1.6.68, 2.1.6.69): a person in
             OU=people, in this site's group and in `directory-admins`, the console's admin group (Keycloak grants it
             the console's admin role), with their full name and e-mail address, and the password they chose in setup,
             or, given none, a one-time password they change at their first sign-in. Never changes an existing
             person's password. Their uid comes from the DC range's admin ids (2.1.6.46; the range's first id is
             fabric-admin's). They are never put in AD's top tier: that is fabric-admin's alone.
    Inputs:  v — fabric vars (site_name, dc_name, ad_password_policy, ldap_groups, posix_home_base,
             posix_login_shell); secrets — fabric's secrets (ad_agent_password); user — the admin's
             user name; email — str; password — a callable returning the password they chose (called only when
             the person is created), or None for a one-time password; container — the DC's container (tests name
             their own); full_name — str, their given names and surname (the last word), default the user name.
    Returns: (state, password): ("created", the one-time password, or None when they chose it) or
             ("exists" / "exists+member", None).
    Fails:   ValidationError from run_op (the directory unreachable or refusing).
    Feeds:   setup/create_admin."""
    group = DIRECTORY_ADMINS
    try:
        run_op(v, secrets, "get_person", {"uid": user}, container)
        state, password = "exists", None
    except ValidationError as e:
        if "no such entry" not in str(e):
            raise
        chosen = password() if password else None
        password = None if chosen else people_password(v)
        users_gid = next((int(g["gidNumber"]) for g in v.get("ldap_groups") or [] if g["name"] == "users"), 5000)
        words = (full_name or user).split()
        first, last = " ".join(words[:-1]) or words[-1], words[-1]
        run_op(v, secrets, "create_person",
               {"uid": user, "first": first, "last": last, "email": email, "password": chosen or password,
                "gid": users_gid, "home_base": v.get("posix_home_base") or "/home",
                "shell": v.get("posix_login_shell") or "/bin/bash", "must_change": not chosen,
                "kind": "admin"}, container)            # an admin's id (2.1.6.46): the first is fabric-admin's
        state = "created"
    if run_op(v, secrets, "add_group_member", {"group": group, "uid": user}, container)["added"] and state == "exists":
        state = "exists+member"
    return state, password
