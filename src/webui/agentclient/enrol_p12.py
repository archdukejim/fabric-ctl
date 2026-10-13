from webui.agentclient.connection import call_agent


def enrol_p12(actor, name, device, legacy):
    """Purpose: A password-protected PKCS#12 for one Android (or other) device (manual 1.5.3.6).
             Agent route: POST /v1/pki/enrol/p12 (pki:enrol), timeout 180 s.
    Inputs:  actor — str user name; name — the certificate's name; device — a directory device or ""; legacy — bool
             (3DES for Android 11 and older).
    Returns: dict from fabriclib.pki.scep.enrol_p12: name, cert, fullchain, der_b64, p12_b64, p12_password (shown
             once), legacy, info, device.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/enrol_post for "p12".
    """
    return call_agent("POST", "/v1/pki/enrol/p12", {"actor": actor, "name": name, "device": device,
                                                    "legacy": bool(legacy)}, timeout=180)
