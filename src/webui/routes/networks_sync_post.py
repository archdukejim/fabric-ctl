import urllib.parse

from webui import agentclient as actions


def networks_sync_post(h, form):
    """Purpose: the Networks tab's Sync now (POST /networks/sync, manual 1.10.4.28, decision 2.1.10.29): one
             fabric-agent call that runs the plan poll at once and publishes BIND's records when DNS waits; then back
             to the tab with what it did, or why it was refused.
    Inputs:  h — the request handler (redirect); form — dict (csrf only; nothing else is read).
    Returns: 303 to /networks with msg (the poll's outcome, Kea restarted or not, the zones published) or err.
    Fails:   AgentError, PermissionDenied (no dhcp:write) and AuthError propagate to handle_request.
    Feeds:   post_action."""
    try:
        res = actions.sync_now()
    except actions.ValidationError as exc:
        return h.redirect("/networks?" + urllib.parse.urlencode({"err": f"Sync now: {exc}"}))
    dns = res.get("dns")
    msg = ("Synced: " + ("Kea restarted" if res.get("kea_restarted") else "Kea already in line")
           + ("; firewall brought in line" if res.get("firewall") else "")
           + ("; DNS published (" + (", ".join(dns.get("zones") or []) or "no zone changed") + ")" if dns
              else "; DNS already in line") + ".")
    return h.redirect("/networks?" + urllib.parse.urlencode({"msg": msg}))
