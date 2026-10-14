from webui import agentclient as actions
from webui import views


def federation_page(h, ctx, query):
    """Purpose: the Federation tab (manual 1.9.8.9): the overview, and with ?rodc_lost=<site> (the admin bundle) the
             accounts a site's lost read-only DC held, with the form that resets them and removes the DC (decision
             2.1.6.58, manual 4.9.1.3).
    Inputs:  h — the request handler (send); ctx — page context; query — dict: rodc_lost, msg, err.
    Returns: 200 the page.
    Fails:   agent errors other than a refusal propagate to handle_request (403 without federation:read, 503 the
             agent down); listing a lost DC's accounts that the agent refuses (400: not below this site, the DC does
             not answer; 403: not the admin bundle) is shown as the page's error.
    Feeds:   get_page."""
    site, lost, err = query.get("rodc_lost", "").strip().lower(), None, query.get("err", "")
    if site:
        try:
            lost = {"site": site, **actions.rodc_lost_plan(site)}
        except (actions.ValidationError, actions.PermissionDenied) as exc:
            err = err or str(exc)
    return h.send(200, views.federation(ctx, actions.federation_overview(), query.get("msg", ""), err, lost))
