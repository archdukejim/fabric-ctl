from webui.devpreview.fabric_rules import ValidationError

# the preview person's groups to manage (2.1.6.67): one they may add to and remove from, one they may only add to
SAMPLE_MANAGED = [{"name": "lab-users", "add": True, "remove": True, "only_from": "", "members": ["sam"]},
                  {"name": "visitors", "add": True, "remove": False, "only_from": "lan", "members": []}]
SAMPLE_PERSON = {"first": "Jim", "last": "Doe", "name": "Jim", "email": "jim@home.arpa", "phone": "+1 555 0100",
                 "mobile": "", "title": "Engineer", "department": "IT", "company": "Example Org", "office": "HQ",
                 "city": "", "state": "", "country": "US", "manager": "", "employee_id": "E-0001"}


def managed(state):
    """Purpose: The preview person's managed groups, kept in the preview's state (changed by Apply).
    Inputs:  state — DevState.
    Returns: list of {"name", "add", "remove", "only_from", "members"}.
    Fails:   never.
    Feeds:   fake_account, fake_pending (a member change's thing)."""
    return state.data.setdefault("managed", [dict(g, members=list(g["members"])) for g in SAMPLE_MANAGED])


def fake_account(state, who, route, body):
    """Purpose: The fake agent's My account (manual 1.8.6.6): GET /v1/account and /v1/account/groups, POST
             /v1/account/password (at once) and /v1/account/groups/<name>/members (a held change, run at Apply), the
             preview person's own, from the sample data.
    Inputs:  state — DevState; who — {"user", "perms"}; route — segments after /v1/; body — dict.
    Returns: the answer in the agent's shapes, or None for another route.
    Fails:   ValidationError as the agent refuses: a wrong current password (the preview's is "current"), a new one
             under 8 characters or the same; a group they do not manage, or a change its controls do not allow.
    Feeds:   fake_agent."""
    if route[:1] != ["account"]:
        return None
    if route == ["account"]:
        return {"uid": who["user"], "person": SAMPLE_PERSON, "groups": ["site-lan", "users"],
                "certs": [{"subject": f"CN={who['user']}", "serial": "1a2b3c", "not_after": "Oct 20 12:00:00 2027 GMT",
                           "status": "valid", "kind": "client"}],
                "devices": [{"name": "jims-laptop", "type": "laptop", "enabled": True, "macs": ["3c:22:fb:10:20:30"],
                             "roles": ["staff"], "vlan": 20}]}
    if route == ["account", "groups"]:
        return {"groups": managed(state)}
    if route == ["account", "password"]:
        if body.get("current") != "current":
            raise ValidationError("the current password is wrong")
        new = str(body.get("new") or "")
        if len(new) < 8 or new == body.get("current"):
            raise ValidationError("the domain's password policy refuses it: at least 8 characters, not the current one")
        return {"uid": who["user"], "changed": True, "sessions_ended": 1}
    if len(route) == 4 and route[1] == "groups" and route[3] == "members":
        group = next((g for g in managed(state) if g["name"] == route[2]), None)
        member, add = str(body.get("member") or ""), body.get("action") == "add"
        if group is None:
            raise ValidationError(f"you do not manage the group {route[2]}")
        if body.get("action") not in ("add", "remove") or not member:
            raise ValidationError("action: add or remove, and a member")
        if not group["add" if add else "remove"]:
            raise ValidationError(f"the group {group['name']} lets its managers {'remove' if add else 'add'} only")
        before = list(group["members"])
        group["members"] = sorted(set(before) | {member}) if add else [m for m in before if m != member]
        return {"uid": who["user"], "group": group["name"], "member": member, "changed": group["members"] != before}
    return None
