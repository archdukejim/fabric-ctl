import urllib.parse

from webui import agentclient as actions

# what each change says when it is done: (segments after the site, message); "{x}" takes the form's field
MESSAGES = [(["block"], "Site number set to {number}."), (["vlans"], "VLAN {id} ({name}) added."),
            (["vlans", "*"], "VLAN saved."), (["vlans", "*", "delete"], "VLAN removed."),
            (["subnets"], "Subnet {cidr} added."), (["subnets", "*"], "Subnet saved."),
            (["subnets", "*", "delete"], "Subnet removed."), (["ranges"], "{kind} range {first} - {last} added."),
            (["ranges", "delete"], "Range removed."), (["addresses"], "{ip} recorded."),
            (["addresses", "*"], "Address saved."), (["addresses", "*", "delete"], "Address removed.")]
FIELDS = {"number", "id", "name", "subnet", "no_subnet", "gateway", "purpose", "notes", "access", "dhcp", "relay",
          "allow_overlap", "split", "force", "vlan", "cidr", "kind", "first", "last", "ip", "mac", "owner", "dns"}


def _message(rest, form):
    """Purpose: the message a change shows when it is done.
    Inputs:  rest — the segments after the site; form — dict.
    Returns: str, or None for a path the tab does not have.
    Fails:   never.
    Feeds:   networks_post."""
    for pattern, text in MESSAGES:
        if len(pattern) == len(rest) and all(p in ("*", r) for p, r in zip(pattern, rest)):
            return text.format(**{k: form.get(k, "") for k in FIELDS})
    return None


def networks_post(h, parts, form):
    """Purpose: route a signed-in, CSRF-checked POST under /networks/<site>/ (manual 1.10.4.21): the site's number,
             VLANs, subnets, ranges and addresses, each one fabric-agent call; then back to the tab, on the subnet the
             form came from, with what happened: applied at once (this site), written for that site's next apply
             (another site), saved but not applied (the apply's output), or refused (why).
    Inputs:  h — the request handler (redirect, deny); parts — URL-decoded segments after /networks/: [<site>, …];
             form — dict (csrf, back: the subnet to show again, and the change's fields).
    Returns: 303 to /networks?site=…[&subnet=…] with msg or err; 404 for an unknown path.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action."""
    if len(parts) < 2 or not parts[0]:
        return h.deny(404, "Not found.")
    site, rest = parts[0], parts[1:]
    msg = _message(rest, form)
    if msg is None:
        return h.deny(404, "Not found.")
    body = {k: x for k, x in form.items() if k in FIELDS and isinstance(x, str)}
    back = {"site": site, **({"subnet": form["back"]} if form.get("back") else {})}
    try:
        res = actions.networks_change(site, rest, body)
    except actions.ValidationError as exc:
        return h.redirect("/networks?" + urllib.parse.urlencode({**back, "err": str(exc)}))
    notes = " ".join(f"Warning: {w}." for w in res.get("warnings") or [])
    if res.get("applied") is False:
        return h.redirect("/networks?" + urllib.parse.urlencode(
            {**back, "err": f"{msg} {notes} Saved, but applying failed: " + (res.get("output") or "")[-300:]}))
    if not res.get("own") and rest != ["block"]:
        msg += f" Written to {res.get('site')}'s plan: it takes effect at that site's next apply."
    elif res.get("applied"):
        msg += " Applied."
    return h.redirect("/networks?" + urllib.parse.urlencode({**back, "msg": f"{msg} {notes}".strip()}))
