from webui.agentclient.connection import call_agent

CHANGES = {"lists", "lists/delete", "rules", "rules/delete", "upstreams", "groups", "groups/delete", "safe-search",
           "fetch"}


def dns_filter_change(what, body):
    """Purpose: Change the DNS filter: a list added or removed, a name allowed or blocked or taken out of the rules, the
             upstreams set, a client group made, changed or removed, safe search set (each saved and applied at once), or
             the lists job started.
             Agent routes: POST /v1/dns-filter/<what> (dns:filter), timeout 300 s.
    Inputs:  what — one of CHANGES; body — the change's fields, as typed (fabriclib checks them).
    Returns: {"result", "applied", "output", "fetching"} (fetch: {"fetching"}).
    Fails:   ValueError for another what (a programming error); the call_agent exceptions: AgentError, ValidationError
             (400: the change refused, nothing saved), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/dns_filter_post."""
    if what not in CHANGES:
        raise ValueError(f"unknown DNS filter change {what!r}")
    return call_agent("POST", f"/v1/dns-filter/{what}", body, timeout=300)
