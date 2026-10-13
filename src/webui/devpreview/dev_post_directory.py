import urllib.parse

from webui import views
from webui.devpreview.fabric_rules import ValidationError, check_password_policy, list_devices, read_policy_changes
from webui.devpreview.sample_data import SAMPLE_DOMAIN


def _person_change(state, ctx, users, target, op, form):
    """Purpose: disable, enable, remove a person or change their groups, in memory, with the agent's refusals (a
             fabric-group member without system:admin; yourself; the user name not typed back).
    Inputs:  state — the dev state; ctx — the page context (user, perms); users — the people list (changed in
             place); target — the person's entry; op — "disable", "enable", "delete" or "groups"; form — dict.
    Returns: str, the query string's msg= or err= part.
    Fails:   never.
    Feeds:   dev_post_directory."""
    uid = target["uid"]
    if set(target["groups"]) - {"users"} and "system:admin" not in ctx["perms"]:
        return urllib.parse.urlencode({"err": f"{uid} is in a fabric group: only an admin can change them"})
    if op in ("disable", "delete") and uid == ctx.get("user"):
        return urllib.parse.urlencode({"err": f"you cannot {'remove' if op == 'delete' else op} yourself"})
    if op == "delete":
        if form.get("confirm", "").strip() != uid:
            return urllib.parse.urlencode({"err": "type the user name to confirm"})
        users.remove(target)
        state.log("PERSON_REMOVE", f"user={uid} (dev preview)")
        return urllib.parse.urlencode({"msg": f"{uid} removed; certificates revoked: 0 (in memory)."})
    if op == "groups":
        group, add = form.get("group", ""), form.get("action") == "add"
        target["groups"] = sorted(set(target["groups"]) | {group} if add else set(target["groups"]) - {group})
        return urllib.parse.urlencode({"msg": f"{uid} {'added to' if add else 'removed from'} {group} (in memory)."})
    target["locked"] = op == "disable"
    state.log("PERSON_DISABLE" if op == "disable" else "PERSON_ENABLE", f"user={uid} (dev preview)")
    return urllib.parse.urlencode({"msg": f"{uid} {op}d (in memory)."})


def _password_policy(h, form):
    """Purpose: the Domain section's password policy saved in memory, checked by fabriclib's own rules (the ones
             fabric-agent runs: read_policy_changes, check_password_policy), refused without domain:admin (403).
    Inputs:  h — the dev handler (send, ctx); form — dict: the policy keys and complexity (on|off).
    Returns: True (403, or a 303 to /directory?view=domain with msg or err).
    Fails:   never for ValidationError (shown as err).
    Feeds:   dev_post_directory."""
    if "domain:admin" not in h.ctx["perms"]:
        h.send(403, views.error_page(403, "Not allowed: you need the permission domain:admin."))
        return True
    try:
        if not read_policy_changes:
            raise ValidationError("the dev preview from the image has no fabriclib; run it from a checkout")
        policy = {**SAMPLE_DOMAIN["policy"], **read_policy_changes(form)}
        check_password_policy(policy)
    except ValidationError as exc:
        h.send(303, b"", location="/directory?" + urllib.parse.urlencode({"view": "domain", "err": str(exc)}))
        return True
    SAMPLE_DOMAIN["policy"] = policy
    h.state.log("AD_PASSWORD_POLICY", "(dev preview: in memory)")
    h.send(303, b"", location="/directory?" + urllib.parse.urlencode(
        {"view": "domain", "msg": "Password policy saved (dev preview: in memory only)."}))
    return True


def dev_post_directory(h, path, form):
    """Purpose: People, devices and roles acted out in memory, with the real fabriclib rules when available.
    Inputs:  h — the dev handler (send, state, ctx); path — /directory/people/<_new|uid>[/reset],
             /directory/domain/password-policy or /directory/<devices|roles>/<name|_new>[/delete|/certs/…]; form —
             dict.
    Returns: True when the path was handled (a result page or a 303 with msg or err was sent); None otherwise (the
             device and role forms need fabriclib).
    Fails:   never for ValidationError (shown as err); other errors propagate.
    Feeds:   dev_post_action."""
    state, ctx = h.state, h.ctx
    if path == "/directory/domain/password-policy":
        return _password_policy(h, {k: v for k, v in form.items() if k != "csrf"})
    if path.startswith("/directory/people/"):
        name, op = (path.split("/")[3:] + ["", ""])[:2]
        users = state.data["people"]["users"]
        if name == "_new":
            uid = form.get("uid", "")
            if not uid or any(u["uid"] == uid for u in users):
                h.send(303, b"", location="/directory?view=people&err=" + urllib.parse.quote(
                    f"{uid or 'a user name'} is missing or already exists"))
                return True
            users.append({"uid": uid, "name": f"{form.get('first', '')} {form.get('last', '')}".strip(),
                          "mail": form.get("email", ""), "locked": False, "groups": ["users"]})
            state.log("PERSON_CREATE", f"user={uid} (dev preview)")
            h.send(200, views.person_result(ctx, uid, "created", "dev-preview-not-real"))
            return True
        if name == "_form":                  # the forms that pick the person
            name = form.get("uid", "")
        target = next((u for u in users if u["uid"] == name), None)
        if op in ("disable", "enable", "delete", "groups") and target:
            h.send(303, b"", location="/directory?view=people&" + _person_change(state, ctx, users, target, op, form))
            return True
        if op != "reset" or not target:
            h.send(404, views.error_page(404, "Not found."))
            return True
        if set(target["groups"]) - {"users"} and "system:admin" not in ctx["perms"]:
            h.send(303, b"", location="/directory?view=people&err=" + urllib.parse.quote(
                f"{name} is in a fabric group: only an admin can reset their sign-in"))
            return True
        state.log("PERSON_RESET", f"user={name} (dev preview)")
        h.send(200, views.person_result(ctx, name, "reset", "dev-preview-not-real"))
        return True
    if not (path.startswith("/directory/") and list_devices):
        return None
    kind, name, op = (path.split("/")[2:] + ["", "", ""])[:3]
    d = state.data["directory"]
    try:
        if name == "_new":
            name = form.get("name", "").strip().lower()
            if any(x["name"] == name for x in d[kind]):
                raise ValidationError(f"{name} already exists")
            state.save(kind, name, form)
            back, msg = {"view": kind[:-1], "name": name}, f"{name} created (in memory)."
        elif op == "delete":
            if kind == "roles" and any(r["members"] for r in d["roles"] if r["name"] == name):
                raise ValidationError(f"role {name} still has devices; take them out first")
            d[kind] = [x for x in d[kind] if x["name"] != name]
            for r in d["roles"]:
                r["members"] = [m for m in r["members"] if m != name]
            back, msg = {"view": kind}, f"{name} deleted (in memory)."
        elif op == "certs":
            for x in d["devices"]:
                if x["name"] == name:
                    x["certs"] = [c for c in x["certs"] if c != form.get("sha256")]
            back, msg = {"view": "device", "name": name}, "Certificate unlinked (in memory)."
        else:
            state.save(kind, name, form)
            back, msg = {"view": kind[:-1], "name": name}, "Saved (in memory)."
        h.send(303, b"", location="/directory?" + urllib.parse.urlencode({**back, "msg": msg}))
    except ValidationError as exc:
        back = {"view": kind} if name == "_new" or op == "delete" else {"view": kind[:-1], "name": name}
        h.send(303, b"", location="/directory?" + urllib.parse.urlencode({**back, "err": str(exc)}))
    return True
