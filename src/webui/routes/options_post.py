import urllib.parse

from webui.routes.held import held

FIELDS = ("action", "scope", "target", "option", "data", "name", "test", "next_server", "server_hostname",
          "boot_file", "code", "type", "record_types", "space", "server", "bios", "uefi", "arm64", "ipxe", "http")
KINDS = ("options", "classes", "option-defs", "netboot")


def _where(where):
    """Purpose: An option's place as the page's select sends it, as the agent's body takes it: "domain" and "site" (a
             set), "class:<domain|site>:<name>" (a class of one), "subnet:<name>", "address:<ip>".
    Inputs:  where — str.
    Returns: dict: scope, target, and domain True for a class of the domain's set.
    Fails:   never (an unknown place is sent as it is; the agent refuses it, saying why).
    Feeds:   options_post."""
    kind, _, rest = where.partition(":")
    if kind == "class":
        owner, _, name = rest.partition(":")
        return {"scope": "class", "target": name, **({"domain": True} if owner == "domain" else {})}
    return {"scope": kind, "target": rest}


def options_post(h, parts, form):
    """Purpose: Route a POST under /networks/options/ (manual 1.10.4.40.1): <kind>, one of options, classes,
             option-defs, netboot, each held for the DHCP options page's Apply (1.10.4.40.2).
    Inputs:  h — the request handler (back, deny); parts — segments after /networks/options/; form — dict: the fields
             of FIELDS, site, view_target (the page to go back to), where (an option's place, _where), picked
             ("<place>|<option>" or "<scope>|<name>" from a select), always_send and array ("on").
    Returns: 303 back to /networks/options (site and target kept) with "Waiting for Apply: …" or the refusal; 404
             for another path.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   networks_post."""
    if len(parts) != 1 or parts[0] not in KINDS:
        return h.deny(404, "Not found.")
    body = {k: form[k] for k in FIELDS if isinstance(form.get(k), str) and form[k]}
    if form.get("site"):
        body["site"] = form["site"]
    picked, _, named = str(form.get("picked") or "").partition("|")
    if parts[0] == "options":
        body.update(_where(picked if picked else str(form.get("where") or "")))
        if picked:
            body["option"] = named
    elif picked:                                   # a class or a definition: its set and its name
        body.update(scope=picked, name=named)
    for flag in ("always_send", "array"):
        if form.get(flag) == "on":
            body[flag] = True
    back = {k: x for k, x in (("site", form.get("site", "")), ("target", form.get("view_target", ""))) if x}
    return held(h, "/networks/options" + ("?" + urllib.parse.urlencode(back) if back else ""), f"ipam/{parts[0]}",
                body)
