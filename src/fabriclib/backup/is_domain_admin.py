from fabriclib.grants.grant_request import grant_request


def is_domain_admin(v, caller, container="samba", request=grant_request):
    """Purpose: whether the caller may use the console's Backups page (manual 1.3.7.12): one of the domain's Domain
             Admins (RID 512, nested membership counted), asked of the DC at each call. Root on the host (caller None)
             is.
    Inputs:  v — rendered vars; caller — the signed-in person's user name, or None (root); container — the DC's
             container; request — grant_request (tests give their own).
    Returns: True or False.
    Fails:   ValidationError from the DC: "the domain controller is not running", or its own refusal.
    Feeds:   agent/require_domain_admin, agent/get_route (backup/allowed)."""
    if caller is None:
        return True
    return bool(request(v, {"op": "domain_admin", "caller": caller}, container).get("member"))
