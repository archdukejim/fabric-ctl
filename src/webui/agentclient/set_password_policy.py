from webui.agentclient.connection import call_agent


def set_password_policy(values):
    """Purpose: Change the domain's password policy, with the checks `fabricctl domain password-policy` makes; the next
             apply writes it into the domain (manual 1.6.5.25).
             Agent route: POST /v1/domain/password-policy (domain:admin).
    Inputs:  values — dict of policy keys to the form's text (minimum_length, history, minimum_age_days,
             maximum_age_days, lockout_threshold, lockout_minutes, lockout_window_minutes: digits; complexity: "on"
             or "off").
    Returns: dict, the saved policy.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403);
             ValidationError naming what the policy refuses (a number out of range, a lockout shorter than its
             window, …).
    Feeds:   src/webui/routes/directory_post (domain).
    """
    return call_agent("POST", "/v1/domain/password-policy", dict(values))["policy"]
