def console_url(v):
    """Purpose: this site's console address as the site selector records it (decision 2.1.8.30, manual 1.8.6.12):
             https and the console's host name, nothing after it.
    Inputs:  v — rendered vars: install_webui (default on), hostname_mgr.
    Returns: "https://<hostname_mgr>", or "" when this site runs no console (its record then holds none, and the
             selector shows it without a link).
    Fails:   never.
    Feeds:   federation/write_site_place (every convergence), federation/join_upstream (the join request's console),
             federation/site_selector (this site's own entry)."""
    host = str(v.get("hostname_mgr") or "").strip().lower().rstrip(".")
    if v.get("install_webui", True) is False or not host:
        return ""
    return f"https://{host}"
