import copy

from fabriclib.dns_filter.check_filter_settings import DEFAULT_UPSTREAMS
from fabriclib.samba.check_password_policy import DEFAULT_POLICY
from fabriclib.settings.constants import LOG_HOST_KEYS, WIZARD_KEYS
from fabriclib.system.host_ram_gb import host_ram_gb


def read_settings(v, have_gb=None):
    """Purpose: the wizard's settings as they are now (manual 1.8.5.2): every key of WIZARD_KEYS with its value, the
             template's default where the settings hold none, never a console-only setting or a secret.
    Inputs:  v — the settings as saved (vars.yaml); have_gb — the host's memory in GB (None: measured), the default
             of host_ram_capacity.
    Returns: {key: value} in WIZARD_KEYS order: install_fluentbit, signin_kerberos bool; dns_filter "bind" or "none";
             log_forwarding without the sub-keys that name something
             on the host (LOG_HOST_KEYS); host_ram_capacity int; ad_password_policy the whole policy (the default's keys
             filled in); dns_filter_upstreams [{address, name}].
    Fails:   never for a readable settings dict.
    Feeds:   export_settings, plan_settings, apply_settings (a stale plan), settings_overview."""
    lf = copy.deepcopy(v.get("log_forwarding") or {})
    if isinstance(lf, dict):
        for part, keys in LOG_HOST_KEYS.items():
            target = lf if not part else lf.get(part)
            for key in keys:
                if isinstance(target, dict):
                    target.pop(key, None)
    policy = v.get("ad_password_policy") or {}
    out = {
        "dns_filter": str(v.get("dns_filter") or "bind").lower(),
        "install_fluentbit": bool(v.get("install_fluentbit", False)),
        "log_forwarding": lf,
        "host_ram_capacity": int(v.get("host_ram_capacity") or (host_ram_gb() if have_gb is None else have_gb) or 4),
        "ad_password_policy": {**DEFAULT_POLICY, **policy} if isinstance(policy, dict) else policy,
        "signin_kerberos": bool(v.get("signin_kerberos", False)),
        "dns_filter_upstreams": copy.deepcopy(v.get("dns_filter_upstreams") or DEFAULT_UPSTREAMS),
    }
    return {k: out[k] for k in WIZARD_KEYS}
