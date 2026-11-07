import time

from webui.agentclient.connection import call_agent

BANNER_SECONDS = 60     # the banner is on every page: asked at most this often per person (1.8.8.2)
_banner = {}


def sizing():
    """Purpose: the signed-in person's sizing alerts, for the Overview's Health (manual 1.8.8.8). Agent route: GET
             /v1/sizing (status:read).
    Inputs:  none.
    Returns: {"at", "size", "alerts", "critical"}.
    Fails:   the call_agent exceptions.
    Feeds:   src/webui/routes/get_page for "/"; sizing_banner."""
    return call_agent("GET", "/v1/sizing")


def sizing_dismiss(resource, user):
    """Purpose: dismiss one sizing alert for this person (2.1.8.39). Agent route: POST /v1/sizing/dismiss (status:read).
    Inputs:  resource — str; user — the signed-in person, whose kept banner goes.
    Returns: {"resource", "level", "objects"}.
    Fails:   the call_agent exceptions.
    Feeds:   src/webui/routes/post_action."""
    out = call_agent("POST", "/v1/sizing/dismiss", {"resource": resource})
    _banner.pop(user, None)
    return out


def sizing_banner(user, perms):
    """Purpose: the banner's alerts on every page while one is critical, for people with settings:admin alone (decision
             2.1.8.38). Kept a minute per person, so a page's request does not ask each time; a failure to ask shows
             no banner, and never stops the page.
    Inputs:  user — the signed-in person; perms — their permissions.
    Returns: list of critical alerts, usually [].
    Fails:   never for the agent's refusals and errors; those give [].
    Feeds:   src/webui/session/page_context."""
    if "settings:admin" not in perms or "status:read" not in perms:
        return []
    kept = _banner.get(user)
    if kept and time.monotonic() - kept[0] < BANNER_SECONDS:
        return kept[1]
    try:
        rows = [a for a in sizing()["alerts"] if a["level"] == "critical"]
    except Exception:               # noqa: BLE001 - the frame without its banner: the page itself still works
        rows = []
    _banner[user] = (time.monotonic(), rows)
    return rows
