"""The setup wizard's sample data for the dev preview: what GET /v1/settings and POST /v1/settings/plan answer."""

SAMPLE_SETTINGS_FORM = {
    "dns_filter": "bind", "install_fluentbit": "false", "log_target": "", "log_target_both": "",
    "host_ram_capacity": "8", "policy_minimum_length": "12", "policy_history": "5", "policy_minimum_age_days": "0",
    "policy_maximum_age_days": "0", "policy_lockout_threshold": "10", "policy_lockout_minutes": "15",
    "policy_lockout_window_minutes": "15", "policy_complexity": "true", "signin_kerberos": "false",
    "logon_policies": "machines | home-machine-admins | home-machine-admins",
    "dns_filter_upstreams": "1.1.1.1 cloudflare-dns.com\n1.0.0.1 cloudflare-dns.com",
}

SAMPLE_SETTINGS = {
    "form": SAMPLE_SETTINGS_FORM,
    "console_only": [
        {"key": "domain", "what": "the DNS domain: permanent", "value": "home.arpa",
         "command": "sudo fabricctl setup (a new install)"},
        {"key": "hostname", "what": "this host's name", "value": "pi-core",
         "command": "sudo fabricctl setup, or the vars editor (sudo fabricctl)"},
        {"key": "host_ip", "what": "this host's LAN address", "value": "192.168.1.10",
         "command": "sudo fabricctl setup, or the vars editor (sudo fabricctl)"},
    ],
    "finished": {"finished": False, "how": "", "by": "", "at": ""},
    "host_gb": 8,
}

SAMPLE_PLAN = {
    "id": "dev-plan", "source": "web",
    "changes": [{"key": "install_fluentbit", "old": "off", "new": "on"},
                {"key": "host_ram_capacity", "old": "8", "new": "6"}],
    "parts": [{"service": "Fluent Bit", "change": "started"}],
    "memory": {"budget_mb": 5632, "rows": [{"service": "Keycloak", "before": 2900, "after": 2100},
                                          {"service": "Fluent Bit", "before": None, "after": 64}]},
    "ignored": [{"key": "webui_oidc_secret", "reason": "a secret"}, {"key": "host_ip", "reason": "console only"}],
}

SAMPLE_SETTINGS_FILE = ("# fabric's settings file (manual 1.8.5.4): DEV PREVIEW sample\nfabric_settings: 1\n"
                        "settings:\n  dns_filter: bind\n  host_ram_capacity: 8\n")
