from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def sudo_rule_change(op, name, users=None, commands=None, run_as=None, hosts=""):
    """Purpose: Add a sudo rule, or remove one of fabric's (manual 1.6.11.7).
             Agent routes: POST /v1/sudo and /v1/sudo/<name>/delete (sudo:admin).
    Inputs:  op — "add" or "delete"; name — the rule's name; users, commands, run_as — lists of text (add); hosts — a
             host group, or "" / "ALL" for every machine of the site (add).
    Returns: dict from fabriclib: {"name", "hosts"} (add); {"name"} (delete).
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
             ValidationError for a bad field, ALL commands to everyone, someone not in the domain, the site's
             default rule or an admin's own (delete).
    Feeds:   src/webui/routes/directory_post (sudo).
    """
    if op == "delete":
        return call_agent("POST", f"/v1/sudo/{quote_segment(name)}/delete")
    return call_agent("POST", "/v1/sudo", {"name": name, "users": users or [], "commands": commands or [],
                                           "run_as": run_as or [], "hosts": hosts or ""})
