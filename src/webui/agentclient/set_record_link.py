from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def set_record_link(actor, key, rtype, index, expected_name, form):
    """Purpose: Link a record of the site's zone from the landing page, or stop linking it (manual 1.4.2.4).
             Agent route: POST /v1/zones/<key>/records/link (dns:write).
    Inputs:  actor — str user name (ignored by the agent for token callers); key — zone key; rtype — "A", "AAAA" or
             "CNAME"; index — int position among that type's records; expected_name — the name the page showed;
             form — mapping: link ("on" links, anything else unlinks), link_label, link_port, link_path ("" when
             absent).
    Returns: the record as saved (fabriclib.dns.set_record_link).
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403);
             ValidationError for another zone or type, a wildcard, a stale record or a bad label, port or path.
    Feeds:   src/webui/routes/landing_post.
    """
    fields = {k: form.get(k, "") for k in ("link", "link_label", "link_port", "link_path")}
    return call_agent("POST", f"/v1/zones/{quote_segment(key)}/records/link",
                      {"actor": actor, "type": rtype, "index": index, "name": expected_name, **fields})
