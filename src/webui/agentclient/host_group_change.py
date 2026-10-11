from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def host_group_change(op, group, machine=""):
    """Purpose: Create or delete a host group, or put a machine in it or take it out (manual 1.6.11.7).
             Agent routes: POST /v1/host-groups, /v1/host-groups/<name>/delete, /v1/host-groups/<name>/members
             (machines:admin).
    Inputs:  op — "create", "delete", "add" or "remove"; group — the host group's short (or AD) name; machine — the
             machine's host name (add and remove).
    Returns: dict from fabriclib: {"name"} (create, delete); {"group", "machine", "member", "changed", "rules"} (add,
             remove).
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
             ValidationError for a bad name, a group or machine the site does not have, a group a sudo rule names.
    Feeds:   src/webui/routes/directory_post (hostgroups).
    """
    if op == "create":
        return call_agent("POST", "/v1/host-groups", {"name": group})
    if op == "delete":
        return call_agent("POST", f"/v1/host-groups/{quote_segment(group)}/delete")
    return call_agent("POST", f"/v1/host-groups/{quote_segment(group)}/members", {"action": op, "machine": machine})
