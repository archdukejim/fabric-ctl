from webui import agentclient as actions
from webui import views
from webui.views.constants import DNS_FILTER_SECTIONS


def dns_filter_page(h, ctx, query, sent=None, err=""):
    """Purpose: Render the DNS filter tab (manual 1.12.2.14): overview, lists, rules, the query log, settings.
    Inputs:  h — the request handler (send); ctx — page context; query — dict: view (a DNS_FILTER_SECTIONS id; anything
             else is the overview), the query log's search (client, name, blocked "on", limit, own "on": fabric's own
             queries too, 2.1.12.12), wait (how often the page has refreshed itself while a fresh install's first
             fetch runs, 2.1.2.22); sent — a refused lists Apply's form ({"on", "shown", "version"}, 1.12.3.17), its
             boxes shown as sent while the lists are still as that page showed them, as they are now when they
             changed since; err — why it was refused.
    Returns: the page (200). Without dns:filter the overview is None (the query log still shows with dns:querylog);
             a search the agent refuses (or an own that is not "on" or empty) shows its reason in place of the
             results.
    Fails:   PermissionDenied without either permission (the handler's 403); other agent errors propagate to
             handle_request (redirect to /login, 503).
    Feeds:   get_page (/dns-filter), dns_filter_post (a refused lists Apply)."""
    ids = [s for s, _ in DNS_FILTER_SECTIONS]
    section = query.get("view") if query.get("view") in ids else "overview"
    try:
        overview = actions.dns_filter_overview()
    except actions.PermissionDenied:
        overview = None
        if section != "querylog":             # with dns:querylog only: the one section it can show
            section = "querylog"
    if sent is not None and (overview or {}).get("lists_version") != sent.get("version"):
        sent = None                            # a stale page: the lists as they are now, not the boxes sent
    search = {k: query.get(k, "") for k in ("client", "name", "blocked", "limit", "own")}
    log, log_err = None, ""
    if section == "querylog" and search["own"] not in ("", "on"):      # the box sends "on" or nothing (2.1.12.12)
        log_err = f"Show fabric's own queries is on or off, not {search['own'][:40]!r}"
    elif section == "querylog":
        try:
            log = actions.query_log(search["client"], search["name"], search["blocked"] == "on",
                                    search["limit"] or 200, search["own"] == "on")
        except actions.PermissionDenied as e:
            if overview is None:                  # neither dns:filter nor dns:querylog: the page is refused (403)
                raise
            log_err = str(e)
        except actions.ValidationError as e:
            log_err = str(e)
    return h.send(200, views.dns_filter(ctx, section, overview, log, search, "", log_err or err, query.get("wait", 0),
                                        sent=sent))
