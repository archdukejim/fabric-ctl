import urllib.parse

from webui import agentclient as actions
from webui import views
from webui.views.constants import GRANT_RIGHTS, KERBEROS_FIELDS, PERSON_FIELDS, POLICY_FIELDS
from webui.routes.device_post import device_post
from webui.routes.held import held, q
from webui.session.page_context import page_context


def _changed_fields(uid, form):
    """Purpose: An Edit form's fields that differ from the person as the DC has them now (1.6.12.4: only what was
             changed is sent; an emptied field clears it).
    Inputs:  uid — the user name; form — dict: PERSON_FIELDS' keys.
    Returns: {field: new value} (empty: nothing changed).
    Fails:   ValidationError from the read (the person or the DC not there); AgentError, PermissionDenied,
             AuthError propagate.
    Feeds:   _person_route (edit)."""
    now = actions.person_overview(uid).get("person") or {}
    return {k: form.get(k, "").strip() for k, _ in PERSON_FIELDS
            if k in form and form.get(k, "").strip() != str(now.get(k) or "")}


def _person_route(uid, op, form):
    """Purpose: A person's change as its agent route and body: disable, enable, remove (the user name typed back),
             groups (add or remove), reset, unlock, edit (the changed fields).
    Inputs:  uid — the user name; op — "disable", "enable", "delete", "groups", "reset", "unlock" or "edit"; form —
             dict (confirm; action, group; PERSON_FIELDS' keys).
    Returns: (route, body).
    Fails:   ValidationError from the read an edit makes, or "nothing changed" (an edit that changes nothing).
    Feeds:   directory_post."""
    if op == "edit":
        body = _changed_fields(uid, form)
        if not body:
            raise actions.ValidationError("nothing changed: no field differs from what the domain has")
        return f"people/{q(uid)}/edit", body
    body = {"delete": {"confirm": form.get("confirm", "")},
            "groups": {"action": form.get("action", ""), "group": form.get("group", "")}}.get(op, {})
    return f"people/{q(uid)}/{op}", body


def _group(h, name, op, form):
    """Purpose: A group's form (manual 1.6.12.5), held on Groups until its Apply: create (form name, description),
             delete, managers (form managers: names separated by commas; add, remove: ticked; only_from) or members
             (form action add|remove, member).
    Inputs:  h — the request handler; name — "_new" or the group's name; op — "", "delete", "managers" or "members";
             form — dict.
    Returns: 303 (held's): to the group's page, to Groups after a create or delete; 404 for another form.
    Fails:   AgentError, PermissionDenied and AuthError propagate.
    Feeds:   directory_post."""
    if name == "_new" and not op:
        return held(h, "/directory/groups", "groups", {"name": form.get("name", "").strip(),
                                                        "description": form.get("description", "").strip()})
    if name in ("", "_new", "_form"):
        return h.deny(404, "Not found.")
    here = f"/directory/groups/{q(name)}"
    if op == "delete":
        return held(h, "/directory/groups", f"groups/{q(name)}/delete")
    if op == "managers":
        return held(h, here, f"groups/{q(name)}/managers", {
            "managers": [m.strip() for m in form.get("managers", "").split(",") if m.strip()],
            "add": bool(form.get("add")), "remove": bool(form.get("remove")),
            "only_from": form.get("only_from", "").strip()})
    if op == "members":
        return held(h, here, f"groups/{q(name)}/members", {"action": form.get("action", ""),
                                                            "member": form.get("member", "").strip()})
    return h.deny(404, "Not found.")


def _machine(h, sess, name, op, form):
    """Purpose: A computer's form (manual 1.6.12.6), held on Computers until its Apply: add (form name, type, managed),
             enable, disable, delete, type (form type, move ticked), sites (form action add|remove, site), move (form
             path), groups (form action add|remove, group: one of its machine groups' members change); keytab (form
             service, user, path) is done at once: it changes nothing and answers the command for the computer's
             administrator (1.6.12.9).
    Inputs:  h — the request handler (send, back, deny); sess — the session (the keytab page's context); name —
             "_new" or the computer's host name; op — the form; form — dict.
    Returns: 303 (held's): to the computer's page, to Computers after an add or a removal; the keytab: 200, the
             command's page, or 303 to the computer's page with the refusal; 404 for another form.
    Fails:   AgentError, PermissionDenied and AuthError propagate.
    Feeds:   directory_post."""
    if name == "_new" and not op:
        return held(h, "/directory/computers", "machines", {
            "name": form.get("name", ""), "managed": "yes" if form.get("managed") == "yes" else "no",
            **({"type": form["type"]} if form.get("type") else {})})
    if name in ("", "_new", "_form"):
        return h.deny(404, "Not found.")
    here = f"/directory/computers/{q(name)}"
    if op in ("enable", "disable", "delete"):
        return held(h, "/directory/computers" if op == "delete" else here, f"machines/{q(name)}/{op}")
    if op == "type":
        return held(h, here, f"machines/{q(name)}/type", {"type": form.get("type", ""),
                                                          "move": bool(form.get("move"))})
    if op == "sites":
        return held(h, here, f"machines/{q(name)}/sites", {"action": form.get("action", ""),
                                                           "site": form.get("site", "")})
    if op == "move":
        return held(h, here, f"machines/{q(name)}/move", {"path": form.get("path", "")})
    if op == "groups":
        return held(h, here, f"host-groups/{q(form.get('group', ''))}/members",
                    {"action": form.get("action", ""), "machine": name})
    if op == "keytab":
        try:
            done = actions.machine_keytab(name, form.get("service", "").strip(), form.get("user", "").strip(),
                                          form.get("path", "").strip())
        except actions.ValidationError as exc:
            return h.back(here, err=str(exc))
        return h.send(200, views.computers(page_context(sess), "keytab", keytab=done))
    return h.deny(404, "Not found.")


def _ou(h, name, op, form):
    """Purpose: An OU's form (manual 1.6.12.7), held on the OUs page until its Apply: create (form parent, name),
             rename (form ou, name) or delete (form ou); an OU is named by its path, so it comes in the form.
    Inputs:  h — the request handler; name — "_new" or "_form"; op — "" (create), "rename" or "delete"; form — dict.
    Returns: 303 (held's): to the tree after a create or a delete, to the OU's page after a rename (its old path: the
             new one is the Apply's); 404 for another form.
    Fails:   AgentError, PermissionDenied and AuthError propagate.
    Feeds:   directory_post."""
    if name == "_new" and not op:
        return held(h, "/directory/ous", "ous", {"parent": form.get("parent", ""),
                                                 "name": form.get("name", "").strip()})
    if name == "_form" and op == "rename":
        back = "/directory/ous?" + urllib.parse.urlencode({"ou": form.get("ou", "")})
        return held(h, back, "ous/rename", {"ou": form.get("ou", ""), "name": form.get("name", "").strip()})
    if name == "_form" and op == "delete":
        return held(h, "/directory/ous", "ous/delete", {"ou": form.get("ou", "")})
    return h.deny(404, "Not found.")


def _grant_fields(form):
    """Purpose: A grant's form as fabric-agent's grant fields (manual 1.6.13.7): its description, who and where
             (names separated by commas), each category's rights from its switches (`<field>_<right>` ticked), sudo
             (every command ticked, or commands separated by commas) and local administrator.
    Inputs:  form — dict.
    Returns: dict of the grant's fields (the DC checks what each may hold).
    Fails:   never.
    Feeds:   _grant."""
    items = lambda key: [x.strip() for x in form.get(key, "").split(",") if x.strip()]    # noqa: E731
    out = {"description": form.get("description", "").strip(), "who": items("who"), "where": items("where"),
           "sudo": ["ALL"] if form.get("sudo_all") else items("sudo"), "local_admin": bool(form.get("local_admin"))}
    out.update({key: [r for r in rights if form.get(f"{key}_{r}")] for key, _, rights in GRANT_RIGHTS})
    return out


def _grant(h, name, op, form):
    """Purpose: A grant's form (manual 1.6.13.7), held on Access until its Apply: add (form name, kind, template and
             the fields), change (the fields; its kind is kept) or remove.
    Inputs:  h — the request handler; name — "_new" or the grant's name; op — "" or "delete"; form — dict.
    Returns: 303 (held's): to Access after an add or a removal, to the grant's page after a change; 404 for another
             form.
    Fails:   AgentError, PermissionDenied and AuthError propagate.
    Feeds:   directory_post."""
    if name == "_new" and not op:
        body = {"name": form.get("name", "").strip(), "kind": form.get("kind") or "allow", **_grant_fields(form),
                **({"template": form["template"]} if form.get("template") else {})}
        return held(h, "/directory/access", "domain/grants", body)
    if name in ("", "_new", "_form", "sync", "explain"):
        return h.deny(404, "Not found.")
    if op == "delete":
        return held(h, "/directory/access", f"domain/grants/{q(name)}/delete")
    if not op:
        return held(h, f"/directory/access/{q(name)}", f"domain/grants/{q(name)}", _grant_fields(form))
    return h.deny(404, "Not found.")


def _host_access(h, kind, name, op, form):
    """Purpose: A machine group form (manual 1.6.11.7), held on Computers (its Machine groups tab), or a sudo rule
             form, held on Policies (1.6.12.10), until its page's Apply.
    Inputs:  h — the request handler; kind — "hostgroups" or "sudo"; name — "_new" (form name; for sudo also users,
             commands, run_as as text separated by commas, hosts), "_form" with op "members" (form group, machine,
             action add|remove), or a group's or rule's name with op "delete"; op — str; form — dict.
    Returns: 303 to its tab (held's), or with "unknown operation" for another form.
    Fails:   AgentError, PermissionDenied and AuthError propagate.
    Feeds:   directory_post."""
    items = lambda key: [x.strip() for x in form.get(key, "").split(",") if x.strip()]    # noqa: E731
    back = "/directory/policies/sudo" if kind == "sudo" else "/directory/computers/_groups"
    if kind == "hostgroups" and name == "_new" and not op:
        return held(h, back, "host-groups", {"name": form.get("name", "")})
    if kind == "hostgroups" and name == "_form" and op == "members":
        return held(h, back, f"host-groups/{q(form.get('group', ''))}/members",
                     {"action": form.get("action", ""), "machine": form.get("machine", "")})
    if kind == "hostgroups" and name not in ("_new", "_form") and op == "delete":
        return held(h, back, f"host-groups/{q(name)}/delete")
    if kind == "sudo" and name == "_new" and not op:
        return held(h, back, "sudo", {"name": form.get("name", ""), "users": items("users"),
                                       "commands": items("commands"), "run_as": items("run_as"),
                                       "hosts": form.get("hosts", "")})
    if kind == "sudo" and name not in ("_new", "_form") and op == "delete":
        return held(h, back, f"sudo/{q(name)}/delete")
    return h.back(back, err="unknown operation")


def directory_post(h, sess, parts, form):
    """Purpose: Devices, device roles, people, machines and Group Policy: each form maps to one fabric-agent call.
    Inputs:  h — the request handler (send, back, deny); sess — dict from find_session; parts — path segments after
             /directory/: ['people', '_new'] (form uid, first, last, email), ['people', <uid>,
             'reset'|'unlock'|'disable'|'enable'|'delete'|'groups'|'edit'] (_person_route's form),
             ['devices'|'roles', '_new'] (form name + fields), ['devices'|'roles', <name>] (save), [..., <name>,
             'delete'], ['devices', <name>, 'certs', 'unlink'] (unlink the certificate in form sha256), ['machines',
             '_new'] (form name, type, managed), ['machines', <name>, 'enable'|'disable'|'delete'|'type'|'sites'|'move'|
             'groups'|'keytab'] (_machine's forms), ['gpo', 'set'|'clear'] (form
             policy, el_<element> values, disabled), ['hostgroups'|'sudo', …] (_host_access' forms),
             ['domain', 'password-policy'] (form: POLICY_FIELDS' keys, complexity on|off), ['domain', 'kerberos',
             'policy'] (form: KERBEROS_FIELDS' keys, whole numbers; held on Kerberos' Apply), ['groups', '_new' |
             <name>, ''|'delete'|'managers'|'members'] (_group's forms), ['ous', '_new' | '_form', ''|'rename'|
             'delete'] (_ou's forms), ['grants', '_new' | <name>, ''|'delete'] (_grant's forms), ['devices'|'roles',
             …] (device_post's forms); form — dict.
    Returns: each change held on its page until the page's Apply (manual 1.8.6.5; a new person's, a reset's and a
             new machine's one-time password is shown once on the page's Review after it): 303 to the page
             (/directory/<section>; a person's change to their page, a removal to People; 802.1X's devices and roles
             to /8021x/devices, /8021x/roles) saying so, or why not.
    Fails:   404 for an unknown kind or operation or a missing name; ValidationError → 303 with the refusal;
             AgentError, PermissionDenied and AuthError propagate.
    Feeds:   post_action (/directory/…).
    """
    kind, name, op = (parts + ["", "", ""])[:3]
    if kind == "people":
        if name == "_new" and not op:
            return held(h, "/directory/people", "people", {k: form.get(k, "") for k in ("uid", "first", "last",
                                                                                          "email")})
        if name not in ("", "_new", "_form") and len(parts) == 3 and op in (
                "reset", "unlock", "disable", "enable", "delete", "groups", "edit"):
            back = "/directory/people" if op == "delete" else f"/directory/people/{q(name)}"
            try:
                route, body = _person_route(name, op, form)
            except actions.ValidationError as exc:
                return h.back(back, err=str(exc))
            return held(h, back, route, body)
        return h.deny(404, "Not found.")
    if kind == "machines" and len(parts) <= 3:
        return _machine(h, sess, name, op, form)
    if kind == "grants" and len(parts) <= 3:
        return _grant(h, name, op, form)
    if kind == "ous" and len(parts) <= 3:
        return _ou(h, name, op, form)
    if kind == "groups" and len(parts) <= 3:
        return _group(h, name, op, form)
    if kind in ("hostgroups", "sudo") and name:
        return _host_access(h, kind, name, op, form)
    if kind == "domain" and name == "password-policy" and not op:
        values = {k: form[k] for k in [f for f, _ in POLICY_FIELDS] + ["complexity"] if k in form}
        return held(h, "/directory/policies", "domain/password-policy", values)
    if kind == "domain" and name == "kerberos" and op == "policy" and len(parts) == 3:
        values = {k: int(form[k]) if form[k].strip().isdigit() else form[k] for k, *_ in KERBEROS_FIELDS if k in form}
        return held(h, "/directory/kerberos", "domain/kerberos/policy", values)
    if kind == "gpo" and name in ("set", "clear") and not op:
        body = {"policy": form.get("policy", ""), "control": bool(form.get("control"))}
        if name == "set":
            body.update(values={k[3:]: val for k, val in form.items() if k.startswith("el_") and val != ""},
                        enabled=not form.get("disabled"))
        return held(h, "/directory/policies/gpo", f"gpo/{name}", body)
    if kind in ("devices", "roles"):
        return device_post(h, parts, form)
    return h.deny(404, "Not found.")
