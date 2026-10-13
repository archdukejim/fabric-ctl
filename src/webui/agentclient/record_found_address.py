from webui.agentclient.connection import call_agent


def record_found_address(ip, kind, mac, name):
    """Purpose: Record an address a scan found in use but unrecorded: a reservation for the MAC the scan saw ("make it
             a reservation?"), or a static address; saved in the plan and applied at once. Agent route:
             POST /v1/ipam/scan/record (dhcp:write), timeout 300 s.
    Inputs:  ip, kind ("reservation" or "static"), mac, name — str as sent by the scan page; checked by fabriclib.
    Returns: {"address": the address as recorded, "warnings": [str], "applied": bool, "output": last 2000 chars}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: a rule of the
             plan, named), AuthError (401), PermissionDenied (403: no dhcp:write).
    Feeds:   src/webui/routes/networks_scan_post."""
    return call_agent("POST", "/v1/ipam/scan/record", {"ip": ip, "kind": kind, "mac": mac, "name": name},
                      timeout=300)
