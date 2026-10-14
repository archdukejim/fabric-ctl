import re

from fabriclib.common.errors import ValidationError
from fabriclib.samba.check_password_policy import check_password_policy
from fabriclib.samba.check_writable_servers import check_writable_servers
from fabriclib.samba.dc_name_problem import dc_name_problem
from fabriclib.samba.suggested_ad_domain import suggested_ad_domain
from fabriclib.setup.common.renew_days import MAX_RENEW_DAYS

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_NETBIOS = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,14}$")


def check_samba_settings(v):
    """Purpose: refuse a Windows-domain configuration fabric cannot provision correctly (manual 1.6.5, 1.1.9.8),
             before anything is rendered: the domain (2.1.6.11), the NetBIOS names, the password policy (2.1.6.13).
    Inputs:  v — rendered settings: ad_domain, domain, dc_name, ad_netbios, ad_password_policy,
             ad_old_password_minutes, ad_rpc_ports, host_join_domain, host_machine_password_renew_days,
             ad_writable_servers (replaced by its trimmed list, check_writable_servers).
    Returns: None.
    Fails:   ValidationError naming the first problem: no or an invalid ad_domain; ad_domain equal to fabric's domain
             (same-domain mode was dropped, 2.1.6.11) or a parent of it; a NetBIOS domain name Windows cannot
             use (more than 15 characters); a DC name it cannot have (dc_name_problem, 2.1.6.45); the password
             policy's (check_password_policy); an invalid old-password window or RPC range; a host_join_domain that
             is not true or false; a host_machine_password_renew_days that is not a whole number from 0 to 999;
             an ad_writable_servers check_writable_servers refuses (2.1.6.57).
    Feeds:   deploy/check_settings."""
    ad, domain = str(v.get("ad_domain") or ""), str(v.get("domain") or "").lower()
    labels = ad.split(".")
    if not ad:
        raise ValidationError("ad_domain is required: the directory's AD domain, chosen once (manual 1.1.9.8; "
                              f"suggested: {suggested_ad_domain(domain) or 'ad.<parent of ' + domain + '>'})")
    if (len(labels) < 2 or not all(_LABEL.match(x) for x in labels) or len(ad) > 253
            or labels[-1] in ("local", "localhost")):
        raise ValidationError(f"ad_domain {ad!r} is not a valid DNS domain of two labels or more")
    if ad == domain:
        raise ValidationError(f"ad_domain cannot be fabric's own domain ({ad}): the AD zone is always a zone of its "
                              f"own (2.1.6.11); suggested: {suggested_ad_domain(domain) or 'a sibling of it'}")
    if domain.endswith("." + ad):
        raise ValidationError(f"ad_domain {ad} is a parent of fabric's domain {domain}: AD's zone would hold "
                              "fabric's (2.1.6.11)")
    if not _NETBIOS.match(str(v.get("ad_netbios") or "")):
        raise ValidationError(f"ad_netbios {v.get('ad_netbios')!r}: at most 15 letters, digits or hyphens")
    problem = dc_name_problem(v.get("dc_name"), v.get("ad_netbios") or "")
    if problem:
        raise ValidationError(f"dc_name, the domain controller's name (2.1.6.45): {problem}")
    policy = v.get("ad_password_policy") or {}
    check_password_policy(policy)
    if not 0 <= int(v.get("ad_old_password_minutes", 0)) <= 99999:
        raise ValidationError("ad_old_password_minutes must be from 0 to 99999")
    if not isinstance(v.get("host_join_domain", True), bool):
        raise ValidationError(f"host_join_domain {v.get('host_join_domain')!r} must be true or false (manual 1.6.11.8)")
    days = v.get("host_machine_password_renew_days", 0)
    if isinstance(days, bool) or not isinstance(days, int) or not 0 <= days <= MAX_RENEW_DAYS:
        raise ValidationError(f"host_machine_password_renew_days {days!r} must be a whole number from 0 (never "
                              f"renewed) to {MAX_RENEW_DAYS} days (manual 1.6.11.12)")
    m = re.fullmatch(r"(\d+)-(\d+)", str(v.get("ad_rpc_ports") or ""))
    if not m or not 1024 < int(m.group(1)) <= int(m.group(2)) <= 65535:
        raise ValidationError(f"ad_rpc_ports {v.get('ad_rpc_ports')!r} must be a range low-high above 1024")
    v["ad_writable_servers"] = check_writable_servers(v.get("ad_writable_servers"))
