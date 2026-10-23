import re
import urllib.parse

from webui import agentclient as actions
from webui import views
from webui.views.constants import POLICY_FIELDS
from webui.session.page_context import page_context


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


def _person_change(uid, op, form):
    """Purpose: Disable, enable or remove a person, or change their groups, through fabric-agent.
    Inputs:  uid — the user name; op — "disable", "enable", "delete" (form confirm: the user name typed back) or
             "groups" (form action add|remove, group); form — dict.
    Returns: str, the message for the people list.
    Fails:   the agentclient exceptions (ValidationError for a refusal).
    Feeds:   directory_post."""
    if op == "delete":
        done = actions.person_action(uid, "delete", {"confirm": form.get("confirm", "")})
        return f"{uid} removed; certificates revoked: {len(done.get('revoked') or [])}."
    if op == "groups":
        done = actions.person_action(uid, "groups", {"action": form.get("action", ""), "group": form.get("group", "")})
        return f"{uid} {'added to' if done['member'] else 'removed from'} {done['group']}" + (
            "." if done["changed"] else " (no change).")
    actions.person_action(uid, op)
    return f"{uid} {op}d: " + ("their sessions ended." if op == "disable" else "they can sign in again.")


def _host_access(kind, name, op, form):
    """Purpose: A host group or sudo rule form (manual 1.6.11.7) as one fabric-agent call.
    Inputs:  kind — "hostgroups" or "sudo"; name — "_new" (form name; for sudo also users, commands, run_as as text
             separated by commas, hosts), "_form" with op "members" (form group, machine, action add|remove), or a
             group's or rule's name with op "delete"; op — str; form — dict.
    Returns: {"msg": …} or {"err": …} for the machines view (an unknown form: {"err": "unknown operation"}).
    Fails:   AgentError, PermissionDenied and AuthError propagate.
    Feeds:   directory_post."""
    items = lambda key: [x.strip() for x in form.get(key, "").split(",") if x.strip()]    # noqa: E731
    try:
        if kind == "hostgroups" and name == "_new" and not op:
            return {"msg": f"host group {actions.host_group_change('create', form.get('name', ''))['name']} created."}
        if kind == "hostgroups" and name == "_form" and op == "members":
            done = actions.host_group_change(form.get("action", ""), form.get("group", ""), form.get("machine", ""))
            return {"msg": f"{done['machine']} {'in' if done['member'] else 'out of'} {done['group']}"
                    + ("." if done["changed"] else " (no change).")}
        if kind == "hostgroups" and name not in ("_new", "_form") and op == "delete":
            return {"msg": f"host group {actions.host_group_change('delete', name)['name']} removed."}
        if kind == "sudo" and name == "_new" and not op:
            done = actions.sudo_rule_change("add", form.get("name", ""), items("users"), items("commands"),
                                            items("run_as"), form.get("hosts", ""))
            return {"msg": f"sudo rule {done['name']} added; hosts: {', '.join(done['hosts']) or 'none yet'}."}
        if kind == "sudo" and name not in ("_new", "_form") and op == "delete":
            return {"msg": f"sudo rule {actions.sudo_rule_change('delete', name)['name']} removed."}
    except actions.ValidationError as exc:
        return {"err": str(exc)}
    return {"err": "unknown operation"}


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
    Returns: a new person, a reset and a new machine: 200 page with the one-time password; the other people changes,
             machines, gpo and the password policy: 303 to their page (/directory/<section>) with what was done or
             why not as its message (hostgroups and sudo: to Machines); devices and roles: 303 to 802.1X's page
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
        try:
            if name == "_new" and not op:
                uid, what = form.get("uid", ""), "created"
                password = actions.create_person(uid, form.get("first", ""), form.get("last", ""),
                                                 form.get("email", ""))
            elif name and op == "reset":
                uid, what = name, "reset"
                password = actions.reset_sign_in(uid)
            elif name and op in ("disable", "enable", "delete", "groups"):
                uid = form.get("uid", "") if name == "_form" else name     # the forms that pick the person
                return h.back("/directory/people", msg=_person_change(uid, op, form))
            else:
                return h.deny(404, "Not found.")
        except actions.ValidationError as exc:
            return h.back("/directory/people", err=str(exc))
        return h.send(200, views.person_result(page_context(sess), uid, what, password))
    if kind == "machines":
        try:
            if name == "_new" and not op:
                machine = form.get("name", "")
                return h.send(200, views.machine_result(page_context(sess), machine,
                                                        actions.add_machine(machine, form.get("type") or None,
                                                                            form.get("managed") == "yes")))
            if name and op in ("enable", "disable", "delete"):
                actions.machine_action(name, op)
                msg = {"enable": f"{name} enabled.", "disable": f"{name} disabled.", "delete": f"{name} removed."}[op]
                return h.back("/directory/machines", msg=msg)
        except actions.ValidationError as exc:
            return h.back("/directory/machines", err=str(exc))
        return h.deny(404, "Not found.")
    if kind in ("hostgroups", "sudo") and name:
        return h.back("/directory/machines", **_host_access(kind, name, op, form))
    if kind == "domain" and name == "password-policy" and not op:
        values = {k: form[k] for k in [f for f, _ in POLICY_FIELDS] + ["complexity"] if k in form}
        try:
            actions.set_password_policy(values)
        except actions.ValidationError as exc:
            return h.back("/directory/domain", err=str(exc))
        return h.back("/directory/domain", msg="Password policy saved. Apply changes writes it into the domain.")
    if kind == "gpo" and name in ("set", "clear") and not op:
        policy = form.get("policy", "")
        values = {k[3:]: val for k, val in form.items() if k.startswith("el_") and val != ""}
        try:
            done = actions.gpo_change(name, policy, values, enabled=not form.get("disabled"),
                                      control=bool(form.get("control")))
        except actions.ValidationError as exc:
            return h.back("/directory/gpo", err=str(exc))
        return h.back("/directory/gpo", msg=f"{policy}: " + ("; ".join(done) or "already so") + ".")
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
