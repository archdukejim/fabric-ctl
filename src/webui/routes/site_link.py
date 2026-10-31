import re

from webui import agentclient as actions

# a console's address as the domain records it (2.1.8.30): https, a host, an optional port, nothing after it
CONSOLE_RE = re.compile(r"^https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$")


def _find(nodes, name):
    """Purpose: one site in the selector's tree.
    Inputs:  nodes — the tree's nodes (each with "children"); name — the site.
    Returns: the node, or None.
    Fails:   never.
    Feeds:   site_link."""
    for n in nodes or []:
        if n.get("site") == name:
            return n
        hit = _find(n.get("children"), name)
        if hit:
            return hit
    return None


def site_link(h, name):
    """Purpose: /sites/<name>, the site selector's link (manual 1.8.6.12): a 303 to that site's own console, its
             address from fabric-agent's list of the domain's sites (never from the request: no open redirect);
             this site's own goes to its Overview.
    Inputs:  h — Handler; name — the one segment after /sites/ ("" for none, or more than one).
    Returns: None; the redirect or the refusal is sent.
    Fails:   404 "No site <name> in the domain." ("No such site." for no name) for a site the list does not hold;
             404 "Site <name> has no console recorded." for one with none (or an address that is not
             https://<host>[:<port>]); agent errors propagate to handle_request.
    Feeds:   routes/get_page."""
    name = name.strip().lower()
    node = _find(actions.site_tree().get("tree"), name) if name else None
    if node and node.get("here"):
        return h.redirect("/")
    if not node:
        return h.deny(404, f"No site {name} in the domain." if name else "No such site.")
    if not CONSOLE_RE.match(str(node.get("console") or "")):
        return h.deny(404, f"Site {name} has no console recorded.")
    return h.redirect(node["console"] + "/")
