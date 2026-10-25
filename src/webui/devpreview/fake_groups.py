from webui.devpreview.fabric_rules import ValidationError

# the preview's groups in show_group's shape (1.6.12.5): one of each kind a page shows differently
_EMPTY = {"grants": [], "sudo": [], "bundle": False, "bundle_name": "", "radius_vlan": None}
SAMPLE_GROUPS = [
    {"name": "directory-admins", "kind": "tier", "description": "The Directory Administrators",
     "scope": {**_EMPTY, "bundle": True, "bundle_name": "admin"},
     "managers": {"managers": [], "add": False, "remove": False, "only_from": ""},
     "members": {"people": ["jim"], "groups": [], "computers": []}},
    {"name": "helpdesk", "kind": "bundle", "description": "fabric's helpdesk bundle",
     "scope": {**_EMPTY, "bundle": True, "bundle_name": "fabric-helpdesk", "grants": [{"name": "lan-helpdesk",
                                                                                       "as": "who"}]},
     "managers": {"managers": [], "add": False, "remove": False, "only_from": ""},
     "members": {"people": [], "groups": [], "computers": []}},
    {"name": "lab-users", "kind": "own", "description": "People of the lab",
     "scope": {**_EMPTY, "sudo": ["lab-restart"], "radius_vlan": 30},
     "managers": {"managers": ["dev"], "add": True, "remove": True, "only_from": ""},
     "members": {"people": ["sam"], "groups": [], "computers": []}},
    {"name": "visitors", "kind": "own", "description": "",
     "scope": dict(_EMPTY), "managers": {"managers": ["dev"], "add": True, "remove": False, "only_from": "site-lan"},
     "members": {"people": [], "groups": [], "computers": []}},
    {"name": "site-lan", "kind": "fabric", "description": "Everyone of site lan",
     "scope": dict(_EMPTY), "managers": {"managers": [], "add": False, "remove": False, "only_from": ""},
     "members": {"people": ["jim", "sam", "lee"], "groups": [], "computers": []}},
    {"name": "Domain Admins", "kind": "ad", "description": "AD's own",
     "scope": dict(_EMPTY), "managers": {"managers": [], "add": False, "remove": False, "only_from": ""},
     "members": {"people": [], "groups": [], "computers": []}},
]
FIXED = ("ad", "computed", "filled", "host-group")


def _groups(state):
    """Purpose: The preview's groups, kept in its state (changed by Apply).
    Inputs:  state — DevState.
    Returns: the list of group dicts.
    Fails:   never.
    Feeds:   fake_groups, fake_pending (a group change's thing)."""
    return state.data.setdefault("groups", [{**g, "scope": dict(g["scope"]), "managers": dict(g["managers"]),
                                             "members": {k: list(v) for k, v in g["members"].items()}}
                                            for g in SAMPLE_GROUPS])


def find_group(state, name):
    """Purpose: One preview group by its name (any case, as AD).
    Inputs:  state — DevState; name — str.
    Returns: the group dict, or None.
    Fails:   never.
    Feeds:   fake_groups, fake_pending."""
    return next((g for g in _groups(state) if g["name"].lower() == str(name).lower()), None)


def _change(state, who, group, action, body):
    """Purpose: A group's delete, managers or members change in memory, with the agent's main refusals.
    Inputs:  state — DevState; who — {"user", "perms"}; group — the group dict; action — str; body — dict.
    Returns: the agent's answer.
    Fails:   ValidationError with the agent's reason.
    Feeds:   fake_groups."""
    admin = "groups:admin" in who["perms"]
    if group["kind"] in FIXED:
        raise ValidationError(f"{group['name']} is managed by fabric: it takes no members or managers here")
    if action == "delete":
        if group["kind"] != "own":
            raise ValidationError(f"{group['name']} is fabric's: only a site's own group is deleted")
        if group["scope"]["sudo"] or group["scope"]["grants"] or group["scope"]["radius_vlan"] is not None:
            raise ValidationError(f"{group['name']} is in use: " + ", ".join(
                [f"sudo rule {r}" for r in group["scope"]["sudo"]] + [f"grant {g['name']}" for g in
                                                                      group["scope"]["grants"]]
                + (["802.1X's people mapping"] if group["scope"]["radius_vlan"] is not None else [])))
        _groups(state).remove(group)
        return {"name": group["name"]}
    if action == "managers":
        if not admin:
            raise ValidationError("only the tier above the group sets its managers")
        before = dict(group["managers"])
        group["managers"] = {"managers": list(body.get("managers") or []), "add": bool(body.get("add")),
                             "remove": bool(body.get("remove")), "only_from": str(body.get("only_from") or "")}
        return {"name": group["name"], **group["managers"], "changed": group["managers"] != before}
    if action == "members":
        add, member = body.get("action") == "add", str(body.get("member") or "").strip()
        if body.get("action") not in ("add", "remove") or not member:
            raise ValidationError("action: add or remove, and a member")
        mgr = group["managers"]
        if not admin and (who["user"] not in mgr["managers"] or not mgr["add" if add else "remove"]):
            raise ValidationError(f"you are not a manager of {group['name']} who may {'add' if add else 'remove'}")
        people = [u["uid"] for u in state.data["people"]["users"]]
        kind = "people" if member in people else "groups" if find_group(state, member) else None
        if kind is None:
            raise ValidationError(f"no such entry: {member}")
        before = list(group["members"][kind])
        group["members"][kind] = sorted(set(before) | {member}) if add else [m for m in before if m != member]
        return {"uid": member, "group": group["name"], "member": add, "changed": group["members"][kind] != before}
    raise ValidationError("unknown operation")


def fake_groups(state, who, route, body):
    """Purpose: The fake agent's groups (manual 1.6.12.5): GET /v1/groups and /v1/groups/<name>; POST /v1/groups,
             /v1/groups/<name>/delete, /managers and /members — in memory.
    Inputs:  state — DevState; who — {"user", "perms"}; route — segments after /v1/; body — dict, or None for a read.
    Returns: the agent's answer, or None for another route.
    Fails:   ValidationError with the agent's reasons (no such group; a name taken or not allowed; fabric's group).
    Feeds:   fake_agent."""
    if route[:1] != ["groups"]:
        return None
    if body is None:                                   # a read
        if route == ["groups"]:
            return {"groups": [{"name": g["name"], "kind": g["kind"], "description": g["description"],
                                "members": sum(len(v) for v in g["members"].values())} for g in _groups(state)]}
        group = find_group(state, route[1]) if len(route) == 2 else None
        if group is None:
            raise ValidationError(f"no group {route[1] if len(route) > 1 else ''} in the domain")
        return group
    if route == ["groups"]:
        name = str(body.get("name") or "").strip()
        if not (2 <= len(name) <= 64) or not all(c.islower() or c.isdigit() or c in "._-" for c in name):
            raise ValidationError("a group's name: 2-64 of a-z 0-9 . _ -")
        if find_group(state, name) or any(u["uid"] == name for u in state.data["people"]["users"]):
            raise ValidationError(f"{name} is already taken")
        _groups(state).append({"name": name, "kind": "own", "description": str(body.get("description") or ""),
                               "scope": dict(_EMPTY), "managers": {"managers": [], "add": False, "remove": False,
                                                                   "only_from": ""},
                               "members": {"people": [], "groups": [], "computers": []}})
        return {"name": name, "gid": 1000123}
    group = find_group(state, route[1]) if len(route) == 3 else None
    if group is None:
        raise ValidationError(f"no group {route[1] if len(route) > 1 else ''} in the domain")
    return _change(state, who, group, route[2], body)
