import re
import urllib.parse

from webui import agentclient as actions
from webui.views.constants import POLICY_FIELDS


def _device_fields(form):
    """Purpose: Turn the device edit form into the fields fabric-agent's save_device takes.
    Inputs:  form — dict from read_form: type, owner, description, macs (space or comma separated), enabled (any
             non-empty value), role_<name> checkboxes.
    Returns: {'type': str, 'owner': str, 'description': str, 'macs': [str], 'enabled': bool, 'roles': [role names]}.
    Fails:   never.
    Feeds:   directory_post → agentclient.save_device."""
    return {"type": form.get("type", ""), "owner": form.get("owner", ""), "description": form.get("description", ""),
            "macs": [m for m in re.split(r"[\s,]+", form.get("macs", "")) if m],
            "enabled": bool(form.get("enabled")),
            "roles": [k[5:] for k, val in form.items() if k.startswith("role_") and val]}


def _role_fields(form):
    """Purpose: Turn the role edit form into the fields fabric-agent's save_role takes.
    Inputs:  form — dict from read_form: description, vlan, priority, perm_<permission> checkboxes.
    Returns: {'description': str, 'vlan': str, 'priority': str, 'permissions': [permissions checked]}.
    Fails:   never.
    Feeds:   directory_post → agentclient.save_role."""
    return {"description": form.get("description", ""), "vlan": form.get("vlan", ""),
            "priority": form.get("priority", ""),
            "permissions": [k[5:] for k, val in form.items() if k.startswith("perm_") and val]}


def _q(segment):
    """Purpose: One agent route segment, quoted (a name with a slash cannot reach another route).
    Inputs:  segment — str.
    Returns: str.
    Fails:   never.
    Feeds:   _held."""
    return urllib.parse.quote(str(segment), safe="")


def _held(h, back, route, body=None):
    """Purpose: Hold a change on its page until the page's Apply (manual 1.8.6.5), and go back to the page saying so.
    Inputs:  h — the request handler (back); back — the page to return to; route — the change's agent route after
             /v1/ (segments quoted); body — its JSON body.
    Returns: 303 to back, with "Waiting for Apply: <the change>" or the refusal (a missing permission, the thing
             unreadable now) as its message.
    Fails:   AgentError, PermissionDenied and AuthError propagate.
    Feeds:   directory_post."""
    try:
        done = actions.hold_change(route, body or {})
    except actions.ValidationError as exc:
        return h.back(back, err=str(exc))
    return h.back(back, msg=f"Waiting for Apply: {done['what']} ({done['pending']} pending on this page).")


def _person_route(uid, op, form):
    """Purpose: A person's change as its agent route and body: disable, enable, remove (the user name typed back),
             groups (add or remove), reset.
    Inputs:  uid — the user name; op — "disable", "enable", "delete", "groups" or "reset"; form — dict (confirm;
             action, group).
    Returns: (route, body).
    Fails:   never.
    Feeds:   directory_post."""
    body = {"delete": {"confirm": form.get("confirm", "")},
            "groups": {"action": form.get("action", ""), "group": form.get("group", "")}}.get(op, {})
    return f"people/{_q(uid)}/{op}", body


def _host_access(h, kind, name, op, form):
    """Purpose: A host group or sudo rule form (manual 1.6.11.7), held on Machines until its Apply.
    Inputs:  h — the request handler; kind — "hostgroups" or "sudo"; name — "_new" (form name; for sudo also users,
             commands, run_as as text separated by commas, hosts), "_form" with op "members" (form group, machine,
             action add|remove), or a group's or rule's name with op "delete"; op — str; form — dict.
    Returns: 303 to Machines (_held's), or with "unknown operation" for another form.
    Fails:   AgentError, PermissionDenied and AuthError propagate.
    Feeds:   directory_post."""
    items = lambda key: [x.strip() for x in form.get(key, "").split(",") if x.strip()]    # noqa: E731
    back = "/directory/machines"
    if kind == "hostgroups" and name == "_new" and not op:
        return _held(h, back, "host-groups", {"name": form.get("name", "")})
    if kind == "hostgroups" and name == "_form" and op == "members":
        return _held(h, back, f"host-groups/{_q(form.get('group', ''))}/members",
                     {"action": form.get("action", ""), "machine": form.get("machine", "")})
    if kind == "hostgroups" and name not in ("_new", "_form") and op == "delete":
        return _held(h, back, f"host-groups/{_q(name)}/delete")
    if kind == "sudo" and name == "_new" and not op:
        return _held(h, back, "sudo", {"name": form.get("name", ""), "users": items("users"),
                                       "commands": items("commands"), "run_as": items("run_as"),
                                       "hosts": form.get("hosts", "")})
    if kind == "sudo" and name not in ("_new", "_form") and op == "delete":
        return _held(h, back, f"sudo/{_q(name)}/delete")
    return h.back(back, err="unknown operation")


def directory_post(h, sess, parts, form):
    """Purpose: Devices, device roles, people, machines and Group Policy: each form maps to one fabric-agent call.
    Inputs:  h — the request handler (send, back, deny); sess — dict from find_session; parts — path segments after
             /directory/: ['people', '_new'] (form uid, first, last, email), ['people', <uid>, 'reset'],
             ['people', <uid> or '_form' (form uid), 'disable'|'enable'|'delete'|'groups'] (_person_change's
             form),
             ['devices'|'roles', '_new'] (form name + fields), ['devices'|'roles', <name>] (save), [..., <name>,
             'delete'], ['devices', <name>, 'certs', 'unlink'] (unlink the certificate in form sha256), ['machines',
             '_new'] (form name), ['machines', <name>, 'enable'|'disable'|'delete'], ['gpo', 'set'|'clear'] (form
             policy, el_<element> values, disabled), ['hostgroups'|'sudo', …] (_host_access' forms),
             ['domain', 'password-policy'] (form: POLICY_FIELDS' keys, complexity on|off); form — dict.
    Returns: people, machines (hostgroups and sudo among them), gpo and the password policy: each change held
             on its page until the page's Apply (manual 1.8.6.5; a new person's, a reset's and a new machine's
             one-time password is shown once on the page's Review after it): 303 to the page (/directory/<section>)
             saying so, or why not; devices and roles: 303 to 802.1X's page
             (/8021x/devices, /8021x/roles) — the new item's page after create, the list after delete, the item's
             page otherwise.
    Fails:   404 for an unknown kind or operation or a missing name; ValidationError → 303 with the refusal (people
             list; the list after a failed create; else the item's page); AgentError, PermissionDenied and AuthError
             propagate.
    Feeds:   post_action (/directory/…).
    """
    user = sess["user"]
    kind, name, op = (parts + ["", "", ""])[:3]
    if kind == "people":
        if name == "_new" and not op:
            return _held(h, "/directory/people", "people", {k: form.get(k, "") for k in ("uid", "first", "last",
                                                                                          "email")})
        if name and op in ("reset", "disable", "enable", "delete", "groups"):
            uid = form.get("uid", "") if name == "_form" else name     # the forms that pick the person
            return _held(h, "/directory/people", *_person_route(uid, op, form))
        return h.deny(404, "Not found.")
    if kind == "machines":
        if name == "_new" and not op:
            return _held(h, "/directory/machines", "machines", {"name": form.get("name", ""),
                                                                "managed": "yes" if form.get("managed") == "yes"
                                                                else "no", **({"type": form["type"]}
                                                                              if form.get("type") else {})})
        if name and op in ("enable", "disable", "delete"):
            return _held(h, "/directory/machines", f"machines/{_q(name)}/{op}")
        return h.deny(404, "Not found.")
    if kind in ("hostgroups", "sudo") and name:
        return _host_access(h, kind, name, op, form)
    if kind == "domain" and name == "password-policy" and not op:
        values = {k: form[k] for k in [f for f, _ in POLICY_FIELDS] + ["complexity"] if k in form}
        return _held(h, "/directory/domain", "domain/password-policy", values)
    if kind == "gpo" and name in ("set", "clear") and not op:
        body = {"policy": form.get("policy", ""), "control": bool(form.get("control"))}
        if name == "set":
            body.update(values={k[3:]: val for k, val in form.items() if k.startswith("el_") and val != ""},
                        enabled=not form.get("disabled"))
        return _held(h, "/directory/gpo", f"gpo/{name}", body)
    if kind not in ("devices", "roles") or not name:
        return h.deny(404, "Not found.")
    listing = f"/8021x/{kind}"
    here = f"{listing}/{urllib.parse.quote(name, safe='')}"
    save, delete = ((actions.save_device, actions.delete_device) if kind == "devices"
                    else (actions.save_role, actions.delete_role))
    fields = _device_fields(form) if kind == "devices" else _role_fields(form)
    try:
        if name == "_new" and not op:
            created = save(user, form.get("name", ""), fields, new=True)["name"]
            back, msg = f"{listing}/{urllib.parse.quote(created, safe='')}", f"{created} created."
        elif op == "delete" and len(parts) == 3:
            delete(user, name)
            back, msg = listing, f"{name} deleted."
        elif kind == "devices" and parts[2:] == ["certs", "unlink"]:     # only the exact unlink route (1.8.6.7)
            actions.link_device_cert(user, name, form.get("sha256", ""), link=False)
            back, msg = here, "Certificate unlinked."
        elif not op:
            save(user, name, fields)
            back, msg = here, "Saved."
        else:
            return h.deny(404, "Not found.")
        return h.back(back, msg=msg)
    except actions.ValidationError as exc:
        return h.back(listing if name == "_new" else here, err=str(exc))
