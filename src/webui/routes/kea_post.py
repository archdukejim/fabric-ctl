from webui import agentclient as actions
from webui.routes.saved_and_applied import saved_and_applied


def _pools(text):
    """Purpose: pools typed one per line (or comma-separated) into a list.
    Inputs:  text — str from a textarea.
    Returns: list of "first - last" strings, blanks dropped.
    Fails:   never.
    Feeds:   _kea."""
    return [p.strip() for line in (text or "").splitlines() for p in line.split(",") if p.strip()]


def _where(form):
    """Purpose: where an option form puts its option: "every subnet", a subnet, a class or a reservation.
    Inputs:  form — dict with scope ("all", "subnet", "class", "mac") and target.
    Returns: {} or {"subnet"|"class"|"mac": target}.
    Fails:   never (the agent refuses an unknown target).
    Feeds:   _kea."""
    scope = form.get("scope", "all")
    return {scope: form.get("target", "")} if scope in ("subnet", "class", "mac") else {}


def _kea(parts, form):
    """Purpose: one Kea tab change, saved and applied by fabric-agent: reservations, subnets, options, classes.
    Inputs:  parts — segments after /kea/: ["on"], ["off"] (manual 1.10.3.5), ["reservations"],
             ["reservations", <mac>, "delete"], ["subnets"],
             ["subnets", "update"], ["subnets", "delete"], ["options"], ["options", "delete"], ["classes"],
             ["classes", <name>, "delete"]; form — dict.
    Returns: (agent result, message), or None for another path.
    Fails:   agent errors propagate (saved_and_applied handles ValidationError).
    Feeds:   kea_post."""
    if parts in (["on"], ["off"]):
        res = actions.set_dhcp_on(parts == ["on"], form.get("interface", ""), form.get("subnet", ""),
                                  form.get("pool", ""), form.get("router", ""))
        nets = ", ".join(res["dhcp"]["subnets"])
        return res, (f"DHCP is on: {nets} on {', '.join(res['dhcp']['interfaces'])}." if parts == ["on"]
                     else "DHCP is off: Kea stopped; its settings and leases are kept.")
    if parts == ["reservations"]:
        res = actions.add_reservation(form.get("mac", ""), form.get("ip", ""), form.get("hostname", ""))
        return res, f"Reserved {res['reservation']['ip']} for {res['reservation']['mac']}."
    if len(parts) == 3 and parts[0] == "reservations" and parts[2] == "delete":
        return actions.remove_reservation(parts[1]), f"Reservation for {parts[1]} removed."
    if parts == ["subnets"]:
        res = actions.add_subnet(form.get("network", ""), form.get("name", ""), form.get("vlan", ""),
                                 form.get("router", ""), _pools(form.get("pools")), form.get("notes", ""),
                                 form.get("allow_overlap", ""))
        return res, f"Subnet {res['subnet']['subnet']} ({res['subnet']['name']}) added."
    if parts == ["subnets", "update"]:
        # a field the form leaves out stays as it is: the overlap with another site is not asked here (1.8.6.14)
        fields = {k: form.get(k, "") for k in ("name", "vlan", "router", "notes", "allow_overlap") if k in form}
        fields.update(add_pools=_pools(form.get("add_pools")), remove_pools=_pools(form.get("remove_pools")))
        res = actions.update_subnet(form.get("subnet", ""), fields)
        return res, f"Subnet {res['subnet']['subnet']} saved."
    if parts == ["subnets", "delete"]:
        res = actions.remove_subnet(form.get("subnet", ""), form.get("force") == "on")
        return res, f"Subnet {res['removed']} removed."
    if parts == ["options"]:
        where = _where(form)
        if form.get("always_send") == "on":
            where["always_send"] = True
        res = actions.set_option(form.get("option", ""), form.get("data", ""), where)
        return res, f"Option {form.get('option')} set for {res['where']}."
    if parts == ["options", "delete"]:
        res = actions.unset_option(form.get("option", ""), _where(form))
        return res, f"Option {form.get('option')} removed from {res['where']}."
    if parts == ["classes"]:
        res = actions.add_client_class(form.get("name", ""), form.get("test", ""), form.get("next_server", ""),
                                       form.get("boot_file", ""))
        return res, f"Client class {res['class']['name']} added."
    if len(parts) == 3 and parts[0] == "classes" and parts[2] == "delete":
        return actions.remove_client_class(parts[1]), f"Client class {parts[1]} removed."
    return None


def kea_post(h, parts, form):
    """Purpose: route a signed-in, CSRF-checked POST under /kea/ (manual 1.10.2.5).
    Inputs:  h — the request handler; parts — URL-decoded segments after /kea/; form — dict.
    Returns: 303 back to /kea with the outcome (saved_and_applied); 404 for an unknown path.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action."""
    return saved_and_applied(h, "/kea", lambda: _kea(parts, form))
