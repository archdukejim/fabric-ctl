from fabriclib.common.errors import ValidationError
from fabriclib.directory.constants import DIRECTORY_ADMINS
from fabriclib.directory.people_password import people_password
from fabriclib.directory.run_op import run_op


def ensure_admin(v, secrets, user, email, password=None, container="samba"):
    """Purpose: the first web UI admin in the directory (manual 1.6.3, 1.6.12.2): a person in OU=people, in this
             site's group and in `directory-admins`, the console's admin group (Keycloak grants it the console's
             admin role; during D1 the first person is put there, 1.6.12.15): with the password they chose in setup
             (2.1.6.33), or, given none, a one-time password they change at their first sign-in. Never changes an
             existing person's password. Their uid is the DC range's first id (2.1.6.46, 2.1.6.63). Their place in
             AD's top tier is setup's (create_admin, at the root: ensure_top_tier).
    Inputs:  v — fabric vars (site_name, dc_name, ad_password_policy, ldap_groups, posix_home_base,
             posix_login_shell); secrets — fabric's secrets (ad_agent_password); user — the admin's
             user name; email — str; password — a callable returning the password they chose (called only when
             the person is created), or None for a one-time password; container — the DC's container (tests name
             their own).
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
        name = user.split(".")[0][:60] or user
        run_op(v, secrets, "create_person",
               {"uid": user, "first": name, "last": name, "email": email, "password": chosen or password,
                "gid": users_gid, "home_base": v.get("posix_home_base") or "/home",
                "shell": v.get("posix_login_shell") or "/bin/bash", "must_change": not chosen,
                "kind": "first_admin"}, container)      # the range's first id (2.1.6.46), an admin's past it
        state = "created"
    if run_op(v, secrets, "add_group_member", {"group": group, "uid": user}, container)["added"] and state == "exists":
        state = "exists+member"
    return state, password
