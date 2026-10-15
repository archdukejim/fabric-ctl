from webui.agentclient.connection import call_agent


def settings_overview():
    """Purpose: what the Settings wizard shows (manual 1.8.5.3): today's wizard settings, its fields filled in with
             them, the console-only settings read only, whether it has been applied once or dismissed. Agent route:
             GET /v1/settings (settings:admin).
    Inputs:  none.
    Returns: {"settings", "form", "console_only", "finished": {"finished", "how", "by", "at"}, "host_gb",
             "interfaces", "dhcp_first_subnet"}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403: without settings:admin).
    Feeds:   src/webui/routes/settings_page, settings_post; get_page (the Overview's Finish setting up).
    """
    return call_agent("GET", "/v1/settings")
