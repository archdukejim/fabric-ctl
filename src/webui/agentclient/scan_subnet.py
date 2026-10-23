from webui.agentclient.connection import call_agent


def scan_subnet(subnet):
    """Purpose: Scan one subnet of this site now, done at once (manual 1.10.4.40.2, 1.10.4.22): which addresses answer,
             and which nobody recorded. Agent route: POST /v1/ipam/scan (dhcp:write), timeout 180 s (a /22 takes about
             12 s; the agent's own limit is 120 s).
    Inputs:  subnet — its name or network; checked by fabriclib.
    Returns: scan_subnet's result: {"subnet", "scanned", "answering": [{"ip", "mac", "how", "status", "kind", "name",
             "note"}], "unrecorded", "at"}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: no grant gives the person networks scan
             here, a subnet not in this site's plan, a scan running, too soon), AuthError (401), PermissionDenied
             (403: no dhcp:write).
    Feeds:   src/webui/routes/networks_scan_post."""
    return call_agent("POST", "/v1/ipam/scan", {"subnet": subnet}, timeout=180)
