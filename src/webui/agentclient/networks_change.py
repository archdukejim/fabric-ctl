from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def networks_change(site, parts, body):
    """Purpose: One change to a site's address plan from the Networks tab; the agent checks it, writes it and, for
             this site's plan, applies it. Agent routes: POST /v1/networks/<site>/block, /vlans[/<id>[/delete]],
             /subnets[/<name>[/delete]], /ranges[/delete], /addresses[/<ip>[/delete]] (dhcp:write), timeout 300 s.
    Inputs:  site — the site's name; parts — the segments after the site (each quoted here, so a name cannot change
             the route); body — dict of text fields as the form sent them. No actor: the agent uses the token's user.
    Returns: {"result", "warnings", "site", "own", "applied" (bool or None), "output"}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: a rule, named; a site this console does not
             show), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/networks_post."""
    path = "/".join(quote_segment(p) for p in [site, *parts])
    return call_agent("POST", f"/v1/networks/{path}", body, timeout=300)
