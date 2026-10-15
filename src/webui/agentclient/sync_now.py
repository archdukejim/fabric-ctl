from webui.agentclient.connection import call_agent


def sync_now():
    """Purpose: Sync now (manual 1.10.4.28): the plan poll at once and, when DNS waits, BIND's records published by the
             quick path; never an apply. Agent route: POST /v1/ipam/sync (dhcp:write), timeout 300 s (Kea's restart and
             BIND's reloads are health-checked).
    Inputs:  none.
    Returns: fabriclib.ipam.sync.sync_plan's result: {"state", "kea_restarted", "firewall", "dns_pending", "dns",
             "why" when nothing is served yet}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: an apply running,
             DHCP off, not upgraded, a step that failed, said with what was done), AuthError (401), PermissionDenied
             (403: no dhcp:write).
    Feeds:   src/webui/routes/networks_sync_post."""
    return call_agent("POST", "/v1/ipam/sync", {}, timeout=300)
