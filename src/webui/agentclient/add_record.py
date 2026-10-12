from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def add_record(actor, key, rtype, form):
    """Purpose: Add one DNS record to a zone in vars.yaml (published by the next apply).
             Agent route: POST /v1/zones/<key>/records (dns:write).
    Inputs:  actor — str user name (the agent uses the token's user instead for the web UI); key — zone key;
             rtype — one of RECORD_TYPES; form — mapping; only name, value (the console's one value field, which
             fills ip, target or text by type: 2.1.2.22), ip, target, text, priority, weight and port are sent (""
             when absent). A landing-page link is set apart (set_record_link, manual 1.4.2.4).
    Returns: the added record as a dict (fabriclib.dns.add_record); the caller reads its "name".
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403);
             ValidationError for a bad type, name or value.
    Feeds:   src/webui/routes/post_action for /bind9/zone/<key>/add.
    """
    fields = {k: form.get(k, "") for k in ("name", "value", "ip", "target", "text", "priority", "weight", "port")}
    return call_agent("POST", f"/v1/zones/{quote_segment(key)}/records", {"actor": actor, "type": rtype, **fields})
