from fabriclib.common.errors import ValidationError
from fabriclib.samba.check_kerberos_policy import DEFAULT
from fabriclib.samba.domain_dc_names import domain_dc_names


def kerberos_overview(v, container="samba"):
    """Purpose: the Kerberos page's facts (manual 1.6.12.9): whether sign-in with the domain logon is on (2.1.6.32;
             turned on or off as Security does today), the realm and its KDCs (the domain's DCs), the ticket policy as
             set.
    Inputs:  v — rendered vars (ad_realm or ad_domain, ad_kerberos_policy, signin_kerberos); container — the DC's
             container.
    Returns: {"realm", "kdcs": [DC names] or None, "kdcs_error": "" or why they could not be read, "policy":
             {"ticket_hours", "renew_days", "skew_minutes"}, "signin_kerberos": bool}.
    Fails:   never for a DC that does not answer (kdcs_error says so).
    Feeds:   agent route GET /v1/domain/kerberos; domain/run_kerberos_command (show)."""
    out = {"realm": str(v.get("ad_realm") or v.get("ad_domain") or "").upper(), "kdcs": None, "kdcs_error": "",
           "policy": {**DEFAULT, **(v.get("ad_kerberos_policy") or {})},
           "signin_kerberos": bool(v.get("signin_kerberos", False))}
    try:
        out["kdcs"] = domain_dc_names(container)["dcs"]
    except ValidationError as e:
        out["kdcs_error"] = str(e)
    return out
