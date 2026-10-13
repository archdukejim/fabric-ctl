from webui.agentclient.connection import call_agent


def enrol_apple(actor, name, device, ssid, wired):
    """Purpose: An Apple configuration profile for one device, with a one-time SCEP challenge (manual 1.5.3.5).
             Agent route: POST /v1/pki/enrol/apple (pki:enrol), timeout 60 s.
    Inputs:  actor — str user name; name — the certificate's name; device — a directory device or ""; ssid — the Wi-Fi
             network's name or ""; wired — bool (a Mac's wired 802.1X).
    Returns: dict from fabriclib.pki.scep.enrol_apple: {"filename", "profile_b64", "expires", "id", "cn"}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: a bad name, an
             unknown device, no SCEP yet), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/enrol_post for "apple".
    """
    return call_agent("POST", "/v1/pki/enrol/apple", {"actor": actor, "name": name, "device": device, "ssid": ssid,
                                                      "wired": bool(wired)}, timeout=60)
