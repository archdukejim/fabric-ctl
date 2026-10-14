from fabriclib.rbac.permissions import SITE_SCOPED


def holds_permission(perms, need):
    """Purpose: whether a person's permissions grant what a route needs, and how (2.1.9.21, manual 1.6.8.2): fully,
             or only in its site helpdesk form (SITE_SCOPED: the same route on this site's own people who hold no
             role), or not at all.
    Inputs:  perms — set of permission names (user_permissions'); need — required_permission's answer (a permission
             name or "session").
    Returns: "full" (held, or "session"), "site" (only the site helpdesk form is held), "" (not held).
    Fails:   never.
    Feeds:   agent/handler.py Handler.authorize; agent/post_people and get_route (narrow to this site's people)."""
    if need == "session" or need in perms:
        return "full"
    if SITE_SCOPED.get(need) in perms:
        return "site"
    return ""
