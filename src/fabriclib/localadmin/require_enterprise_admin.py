from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError

ONLY = ("only the Enterprise Admin (fabric-admin signed in, or root on this host) may {what} (decisions 2.1.6.78, "
        "2.1.7.18)")


def require_enterprise_admin(v, caller, what, container="samba", check=check_access):
    """Purpose: the Enterprise Admin's tier, or a refusal (decisions 2.1.6.78, 2.1.7.18, 2.1.7.19): the DC's host's
             local-admin is released, and its SSH switch set, only to it. Root on the host (caller None) acts for it;
             a person is asked of the DC (fabric-agent's check, 1.6.12.17.2): AD's top tier passes, a Directory
             Administrator or anyone below is refused.
    Inputs:  v — rendered vars; caller — the signed-in person's user name, or None (root); what — the action, for the
             refusal ("check out local-admin's password"); container — the DC's container; check — check_access
             (tests give their own).
    Returns: None.
    Fails:   ValidationError: ONLY for anyone below the top tier; the DC's own word when it does not answer or the
             caller is no person of the domain.
    Feeds:   checkout_local_admin, set_local_admin_ssh."""
    if caller is None:
        return
    try:
        tier = check(v, caller, "domain:admin", None, container=container)["tier"]
    except ValidationError as e:
        if "only a Directory Administrator" in str(e):
            raise ValidationError(ONLY.format(what=what))
        raise
    if tier != "enterprise":
        raise ValidationError(ONLY.format(what=what))
