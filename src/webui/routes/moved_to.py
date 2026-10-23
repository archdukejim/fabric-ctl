import urllib.parse

from webui.views.constants import DIRECTORY_SECTIONS, OPENBAO_VIEWS

# what the old address's query keeps (the rest, msg and err among them, is dropped: 1.8.6.7)
_KEEP = ("zone", "view", "device", "slot", "step", "match", "client", "name", "blocked", "limit")


def _with(path, query, drop=()):
    """Purpose: A new address with the old query's kept keys.
    Inputs:  path — the new path; query — dict of the old address's query; drop — keys left out.
    Returns: str.
    Fails:   never.
    Feeds:   moved_to."""
    kept = {k: query[k] for k in _KEEP if k in query and k not in drop and query[k]}
    return path + ("?" + urllib.parse.urlencode(kept) if kept else "")


def moved_to(path, query):
    """Purpose: Where a page that moved in 0.8.0 lives now (manual 1.8.6.4: the old addresses answer with a redirect).
    Inputs:  path — the requested path; query — dict of its query string.
    Returns: the new address (path and the query it keeps), or None when the path did not move.
    Fails:   never.
    Feeds:   get_page (303 to it), and the dev preview through it."""
    q = urllib.parse.quote
    if path == "/bind9":
        return _with("/dns/zones", query)
    if path == "/stepca":
        if query.get("view") == "acme":
            return "/pki/acme"
        return _with("/pki", query)
    if path == "/openbao":
        view = query.get("view") if query.get("view") in OPENBAO_VIEWS else "status"
        return _with("/secrets" + ("" if view == "status" else "/" + view), query, drop=("view",))
    if path == "/freeradius":
        if query.get("view") in ("switches", "windows"):
            return _with("/8021x/guides", query)
        return "/8021x"
    if path == "/security":
        return "/settings/sign-in"
    if path.startswith(("/directory/devices", "/directory/roles")):
        return "/8021x" + path[len("/directory"):]
    if path == "/directory" and query.get("view"):      # /directory alone is the Directory's Overview now
        view, name = query.get("view", ""), query.get("name", "")
        if view == "device" and name:
            return f"/8021x/devices/{q(name, safe='')}"
        if view == "role" and name:
            return f"/8021x/roles/{q(name, safe='')}"
        if view in ("devices", "device"):
            return "/8021x/devices"
        if view in ("roles", "role"):
            return "/8021x/roles"
        if view in dict(DIRECTORY_SECTIONS):
            return _with(f"/directory/{view}", query, drop=("view", "name"))
        return "/directory"
    return None
