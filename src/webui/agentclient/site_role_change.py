from webui.agentclient.connection import call_agent


def site_role_change(site, role, member, action):
    """Purpose: Grant a role at a site below this one, or take it back (manual 1.9.8.20, 2.1.9.21).
             Agent route: POST /v1/federation/roles (federation:admin).
    Inputs:  site — the site's name; role — a grantable role; member — a group or person ("" for <site>-admins);
             action — "grant", "revoke" or "remake" (the site's group made again; role "admins" too).
    Returns: dict from fabriclib change_site_role: {"site", "role", "group", "member", "granted", "changed"}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: this site
             itself, a site not below it, an unknown role or member), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/federation_post.
    """
    return call_agent("POST", "/v1/federation/roles", {"site": site, "role": role, "member": member,
                                                        "action": action})
