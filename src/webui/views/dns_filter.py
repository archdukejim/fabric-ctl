import time

from webui.views.constants import DNS_FILTER_SECTIONS
from webui.views.render_page import render_page

# a fresh install's first fetch (2.1.2.22 item 1): the tab reloads itself every REFRESH_SECONDS, at most REFRESH_TIMES
REFRESH_SECONDS, REFRESH_TIMES = 10, 30


def _ago(ts):
    """Purpose: how long ago a time was, for the lists' state.
    Inputs:  ts — seconds since the epoch, or None.
    Returns: "never", "5 min ago", "3 h ago" or "2 days ago".
    Fails:   never.
    Feeds:   dns_filter."""
    if not ts:
        return "never"
    s = max(0, int(time.time() - ts))
    return f"{s // 60} min ago" if s < 7200 else f"{s // 3600} h ago" if s < 172800 else f"{s // 86400} days ago"


def _first_fetch_pending(overview):
    """Purpose: whether the lists job has still to bring a first copy (a fresh install: the lists and the catalogue
             arrive a minute or so after setup, 2.1.2.22 item 1).
    Inputs:  overview — filter_overview's dict, or None.
    Returns: True while the filter is on and the catalogue has not been read, or a ticked list has never been fetched
             (no copy and no failed attempt either); False otherwise. A failed fetch ends the wait: it shows as failed.
    Fails:   never.
    Feeds:   dns_filter."""
    if not overview or not overview.get("on"):
        return False
    return not overview.get("catalogue_fetched") or any(
        lst.get("enabled") and not lst.get("last_success") and not lst.get("last_fetch")
        for lst in overview.get("lists") or [])


def dns_filter(ctx, section, overview, log, search, msg="", err="", wait=0):
    """Purpose: The DNS filter tab (manual 1.12.2.14): the statistics, the lists (and AdGuard's catalogue to add from),
             the rules, the query log with Allow / Block from a line, and the upstreams.
    Inputs:  ctx — page context; section — a DNS_FILTER_SECTIONS id; overview — filter_overview's dict, or None
             without dns:filter; log — query_log's result or None; search — the query log's search (client, name,
             blocked, limit); msg, err — flash texts; wait — how many times the page has refreshed itself while the
             first fetch runs (the query's wait).
    Returns: HTML str. On the overview and lists sections, while _first_fetch_pending, the page carries a meta refresh
             (no script: the strict CSP) to itself with wait + 1, every REFRESH_SECONDS, at most REFRESH_TIMES times;
             then it stops and says so.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads a key the caller left out).
    Feeds:   src/webui/routes/dns_filter_page; devserver."""
    peak = max([h["queries"] for h in ((overview or {}).get("stats") or {}).get("hours") or []] or [1])
    pending = section in ("overview", "lists") and _first_fetch_pending(overview)
    wait = int(wait) if str(wait).isdigit() else 0
    refresh = {"seconds": REFRESH_SECONDS, "url": f"/dns-filter?view={section}&wait={wait + 1}"} if (
        pending and wait < REFRESH_TIMES) else None
    return render_page("dns_filter", ctx=ctx, tab="dnsfilter", sections=DNS_FILTER_SECTIONS, view=section,
                       d=overview, log=log, search=search, peak=peak, ago=_ago, msg=msg, err=err, refresh=refresh,
                       stalled=pending and not refresh)
