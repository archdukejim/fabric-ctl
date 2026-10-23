import urllib.parse

from webui.routes.held import held, q


def zones_post(h, user, parts, form):
    """Purpose: DNS zones: add one, or remove one with its records, each held for DNS' Apply (decision 2.1.8.18); at
             Apply BIND and the DNS filter take it within seconds.
    Inputs:  h — the request handler (back, deny); user — the signed-in person (unused: the hold is the session's);
             parts — URL-decoded segments after /bind9/zones/: ['new'] (form name, hide_public) or [<key>, 'remove']
             (form confirm: the name typed again); form — dict.
    Returns: 303 to Forward zones (an add) or the zone's page (a removal) saying it waits for Apply, or the refusal;
             the agent's own refusals (a name taken, the site's own zone, a confirmation that is not the name) come at
             Apply, on the Review.
    Fails:   404 for another path; AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/bind9/zones/…)."""
    if parts == ["new"]:
        return held(h, "/dns/zones", "zones", {"name": form.get("name", ""),
                                               "hide_public": bool(form.get("hide_public"))})
    if len(parts) == 2 and parts[1] == "remove":
        back = "/dns/zones?zone=" + urllib.parse.quote(parts[0], safe="")
        return held(h, back, f"zones/{q(parts[0])}/delete", {"confirm": form.get("confirm", "")})
    return h.deny(404, "Not found.")
