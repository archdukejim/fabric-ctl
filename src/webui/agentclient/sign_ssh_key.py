from webui.agentclient.connection import call_agent


def sign_ssh_key(actor, public_key):
    """Purpose: An 8-hour SSH user certificate for a fabric admin's public key (manual 1.6.11.9.3).
             Agent route: POST /v1/ssh/sign (any sign-in; refused outside the fabric admins), timeout 60 s.
    Inputs:  actor — str user name (the agent uses the token's); public_key — one OpenSSH public key line.
    Returns: dict from fabriclib.vault.ssh.sign_ssh_key: certificate, serial, principal, valid_hours, key_id,
             fingerprint, type.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: off, not a fabric
             admin, a key refused), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/ssh_post for "sign".
    """
    return call_agent("POST", "/v1/ssh/sign", {"actor": actor, "public_key": public_key}, timeout=60)
