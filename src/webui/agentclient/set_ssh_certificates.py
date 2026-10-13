from webui.agentclient.connection import call_agent


def set_ssh_certificates(actor, on):
    """Purpose: Turn SSH certificates for the fabric admins on or off (manual 1.6.11.9.1).
             Agent route: POST /v1/ssh/on or /v1/ssh/off (system:admin), timeout 120 s.
    Inputs:  actor — str user name; on — bool.
    Returns: {"on", "public_key", "fingerprint", "changed"}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: OpenBao refusing
             or locked), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/ssh_post for "on" and "off".
    """
    return call_agent("POST", "/v1/ssh/on" if on else "/v1/ssh/off", {"actor": actor}, timeout=120)
