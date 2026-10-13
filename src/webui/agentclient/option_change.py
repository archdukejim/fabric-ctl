from webui.agentclient.connection import call_agent

ROUTES = {"options": "/v1/ipam/options", "classes": "/v1/ipam/classes", "option-defs": "/v1/ipam/option-defs",
          "netboot": "/v1/ipam/netboot", "option-editors": "/v1/ipam/option-editors"}


def option_change(kind, org, body):
    """Purpose: One change of the DHCP options page (manual 1.10.4.24.6), saved and applied by fabric-agent. Agent
             routes: POST /v1/ipam/options, /v1/ipam/classes, /v1/ipam/option-defs, /v1/ipam/netboot (dhcp:write);
             /v1/ipam/options/org, /classes/org, /option-defs/org, /v1/ipam/option-editors (dhcp:org-options);
             timeout 300 s (an apply).
    Inputs:  kind — a key of ROUTES; org — bool, the organisation's form of the route; body — dict of the route's
             fields as typed. No actor: the agent uses the token's user.
    Returns: {"what", "result", "warnings", "site", "applied" (bool, None for another site's change), "output"}.
    Fails:   KeyError for an unknown kind; the call_agent exceptions: AgentError, ValidationError (400: what fabriclib
             refuses, AD refusing a site the top has not added), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/options_post."""
    path = ROUTES[kind] + ("/org" if org and kind in ("options", "classes", "option-defs") else "")
    return call_agent("POST", path, body, timeout=300)
