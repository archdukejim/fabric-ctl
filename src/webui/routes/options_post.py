import urllib.parse

from webui import agentclient as actions

FIELDS = ("action", "scope", "site", "target", "option", "data", "name", "test", "next_server", "server_hostname",
          "boot_file", "code", "type", "record_types", "space", "server", "bios", "uefi", "arm64", "ipxe", "http")
KINDS = ("options", "classes", "option-defs", "netboot", "option-editors")


def _message(kind, res):
    """Purpose: what the page says after a change.
    Inputs:  kind — the change's kind; res — the agent's answer.
    Returns: str.
    Fails:   never.
    Feeds:   options_post."""
    done = {"options": "Option saved", "classes": "Client classes saved", "option-defs": "Option definitions saved",
            "netboot": "Netboot preset saved", "option-editors": "Who may edit the organisation's options is saved"}
    text = done[kind] + "."
    if res.get("applied") is None and kind != "option-editors":
        text += " It is in that site's plan: its Kea takes it within 30 seconds."
    for w in res.get("warnings") or []:
        text += f" Note: {w}."
    return text


def options_post(h, parts, form):
    """Purpose: route a signed-in, CSRF-checked POST under /kea/options/ (manual 1.10.4.24.6): <kind>[/org], kind one of
             options, classes, option-defs, netboot, option-editors; each one fabric-agent call that saves and (for
             this site or the organisation) applies at once.
    Inputs:  h — the request handler (redirect, deny); parts — URL-decoded segments after /kea/options/; form — dict
             (the fields of FIELDS; checkboxes org, always_send, array as "on").
    Returns: 303 back to /kea/options (site and target kept) with msg, or err when the agent refused or the apply
             failed; 404 for an unknown path.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action."""
    if not parts or parts[0] not in KINDS or parts[1:] not in ([], ["org"]):
        return h.deny(404, "Not found.")
    body = {k: form[k] for k in FIELDS if form.get(k)}
    for flag in ("org", "always_send", "array"):
        if form.get(flag) == "on":
            body[flag] = True
    org = parts[1:] == ["org"]
    if parts[0] == "options" and org:
        body.setdefault("scope", "org")
    back = {k: form[k] for k in ("site", "view_target") if form.get(k)}
    back = {"site": back.get("site", ""), "target": back.get("view_target", "")}
    try:
        res = actions.option_change(parts[0], org, body)
        if res.get("applied") is False:
            back["err"] = _message(parts[0], res) + " Saved, but applying failed: " + res.get("output", "")[-300:]
        else:
            back["msg"] = _message(parts[0], res)
    except actions.ValidationError as exc:
        back["err"] = str(exc)
    return h.redirect("/kea/options?" + urllib.parse.urlencode({k: x for k, x in back.items() if x}))
