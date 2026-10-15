from fabriclib.samba.check_password_policy import POLICY_KEYS


def _log_target(lf):
    """Purpose: where the logs go, as the wizard's one line.
    Inputs:  lf — log_forwarding (read_settings).
    Returns: "host:port", the URL, or "" for nowhere.
    Fails:   never.
    Feeds:   form_from_settings."""
    syslog, elastic = (lf or {}).get("syslog") or {}, (lf or {}).get("elastic") or {}
    if syslog.get("host"):
        return f"{syslog['host']}:{syslog.get('port', 6514)}"
    return str(elastic.get("url") or "")


def form_from_settings(values):
    """Purpose: the wizard's fields filled in with settings (manual 1.8.5.3: Reconfigure starts from today's values),
             the inverse of settings_from_form.
    Inputs:  values — {wizard key: value} (read_settings, or what was typed so far).
    Returns: {field: text} — the fields settings_from_form reads, and log_target_both: "yes" when the logs go to a
             syslog server and Elasticsearch both (the one line cannot hold both: that field is then not offered).
    Fails:   never for read_settings' values.
    Feeds:   settings/settings_overview (GET /v1/settings)."""
    yes = {True: "true", False: "false"}
    lf = values.get("log_forwarding") or {}
    policy = values.get("ad_password_policy") or {}
    dhcp = values.get("dhcp") or {}
    lines = []
    for ou, rights in (values.get("logon_policies") or {}).items():
        lines.append(f"{ou or 'site'} | {', '.join(rights.get('console') or [])} | "
                     f"{', '.join(rights.get('remote') or [])}")
    form = {"install_kea": yes[bool(values.get("install_kea"))],
            **{f"dhcp_{k}": str(dhcp.get(k) or "") for k in ("interface", "subnet", "pool", "router")},
            "dns_filter": str(values.get("dns_filter") or "bind"),
            "install_fluentbit": yes[bool(values.get("install_fluentbit"))],
            "log_target": _log_target(lf),
            "log_target_both": "yes" if lf.get("syslog") and lf.get("elastic") else "",
            "host_ram_capacity": str(values.get("host_ram_capacity") or ""),
            **{f"policy_{k}": str(policy.get(k, "")) for k in POLICY_KEYS},
            "policy_complexity": yes[bool(policy.get("complexity", True))],
            "signin_kerberos": yes[bool(values.get("signin_kerberos"))],
            "logon_policies": "\n".join(lines),
            "dns_filter_upstreams": "\n".join(f"{u.get('address', '')} {u.get('name', '')}"
                                              for u in values.get("dns_filter_upstreams") or [])}
    return form
