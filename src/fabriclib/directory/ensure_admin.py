from fabriclib.common.errors import ValidationError
from fabriclib.directory.people_password import people_password
from fabriclib.directory.run_op import run_op


def ensure_admin(v, secrets, user, email, password=None, container="samba"):
    """Purpose: the first web UI admin in the directory (manual 1.6.3): a person of this site, in the web UI's admin
             group (Keycloak grants it the console's admin role) and in `fabric-admins` (the hosts, 1.6.11.2):
             with the password they chose in setup (2.1.6.33),
             or, given none, a one-time password they change at their first sign-in. Never changes an existing
             person's password. Their uid is the site block's first id where the block is laid out in ranges
             (2.1.6.46, manual 1.6.3.17).
    Inputs:  v — fabric vars (site_name, webui_admin_group (default admins), ad_password_policy, ldap_groups,
             posix_home_base, posix_login_shell); secrets — fabric's secrets (ad_agent_password); user — the admin's
             user name; email — str; password — a callable returning the password they chose (called only when
             the person is created), or None for a one-time password; container — the DC's container (tests name
             their own).
    Returns: (state, password): ("created", the one-time password, or None when they chose it) or
             ("exists" / "exists+member", None).
    Fails:   ValidationError from run_op (the directory unreachable or refusing).
    Feeds:   setup/create_admin."""
    group = v.get("webui_admin_group") or "admins"
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
                "kind": "first_admin"}, container)      # the block's first id (2.1.6.46), an admin's past it
        state = "created"
    if run_op(v, secrets, "add_group_member", {"group": group, "uid": user}, container)["added"] and state == "exists":
        state = "exists+member"
    # the installer's one person manages the hosts too (manual 1.6.11.2): without them fabric-admins starts empty
    run_op(v, secrets, "add_group_member", {"group": "fabric-admins", "uid": user}, container)
    return state, password
