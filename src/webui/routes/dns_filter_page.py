from webui import agentclient as actions
from webui import views
from webui.views.constants import DNS_FILTER_SECTIONS


def dns_filter_page(h, ctx, query):
    """Purpose: Render the DNS filter tab (manual 1.12.2.14): overview, lists, rules, the query log, settings.
    Inputs:  h — the request handler (send); ctx — page context; query — dict: view (a DNS_FILTER_SECTIONS id; anything
             else is the overview), the query log's search (client, name, blocked "on", limit), wait (how
             often the page has refreshed itself while a fresh install's first fetch runs, 2.1.2.22).
    Returns: the page (200). Without dns:filter the overview is None (the query log still shows with dns:querylog);
             a search the agent refuses shows its reason in place of the results.
    Fails:   PermissionDenied without either permission (the handler's 403); other agent errors propagate to
             handle_request (redirect to /login, 503).
    Feeds:   get_page (/dns-filter)."""
    ids = [s for s, _ in DNS_FILTER_SECTIONS]
    section = query.get("view") if query.get("view") in ids else "overview"
    try:
        overview = actions.dns_filter_overview()
    except actions.PermissionDenied:
        overview = None
        if section != "querylog":             # with dns:querylog only: the one section it can show
            section = "querylog"
    search = {k: query.get(k, "") for k in ("client", "name", "blocked", "limit")}
    log, log_err = None, ""
    if section == "querylog":
        try:
            log = actions.query_log(search["client"], search["name"], search["blocked"] == "on",
                                    search["limit"] or 200)
        except actions.PermissionDenied as e:
            if overview is None:                  # neither dns:filter nor dns:querylog: the page is refused (403)
                raise
            log_err = str(e)
        except actions.ValidationError as e:
            log_err = str(e)
    return h.send(200, views.dns_filter(ctx, section, overview, log, search, "", log_err, query.get("wait", 0)))
