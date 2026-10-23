import re

from webui.devpreview.fabric_rules import ValidationError

PEOPLE_RIGHTS = ("edit", "reset", "unlock", "disable", "add")
MACHINE_RIGHTS = ("add", "move", "disable", "remove", "groups")
SIGNIN_RIGHTS = ("keyboard", "remote")
FIELDS = {"kind": "allow", "description": "", "who": [], "where": [], "people": [], "machines": [], "signin": [],
          "sudo": [], "local_admin": False}
TIERS = ("directory-admins", "dc-hosts", "Enterprise Admins", "Domain Admins", "Schema Admins")
TEMPLATES = {"helpdesk": {"description": "a help desk: people's details, passwords and lockouts (manual 1.6.13.5)",
                          "people": ["edit", "reset", "unlock"]},
             "limited-directory-administrator": {
                 "description": "every category, on the groups it is given (manual 1.6.13.5, 2.1.6.68)",
                 "people": list(PEOPLE_RIGHTS), "machines": list(MACHINE_RIGHTS), "signin": list(SIGNIN_RIGHTS),
                 "sudo": ["ALL"], "local_admin": True}}
# the preview's grants: three shipped, one for the help desk; who and where reach the preview's people and computers
SAMPLE_GRANTS = [
    {**FIELDS, "name": "server-administrators", "description": "the servers' administrators (manual 1.6.13.5)",
     "who": ["server-admins"], "where": ["machines-servers"], "signin": ["keyboard", "remote"], "sudo": ["ALL"],
     "local_admin": True, "_people": ["jim"], "_machines": ["host-1"]},
    {**FIELDS, "name": "desktops", "description": "every person signs in at the desktops (manual 1.6.13.5)",
     "who": ["Domain Users"], "where": ["machines-desktops"], "signin": ["keyboard"],
     "_people": ["jim", "sam", "lee"], "_machines": ["jims-laptop"]},
    {**FIELDS, "name": "network-administrators", "description": "the network machines' administrators",
     "who": ["network-admins"], "where": ["machines-network"], "signin": ["keyboard", "remote"], "sudo": ["ALL"],
     "local_admin": True, "_people": [], "_machines": []},
    {**FIELDS, "name": "lan-helpdesk", "description": "", "who": ["helpdesk"], "where": ["site-lan"],
     "people": ["edit", "reset", "unlock"], "_people": ["sam"], "_machines": ["host-1", "jims-laptop"],
     "_where_people": ["jim", "sam", "lee"]},
]


def _grants(state):
    """Purpose: The preview's grants, kept in its state (changed by Apply).
    Inputs:  state — DevState.
    Returns: list of dicts (the stored fields and the preview's own reach, keys starting with _).
    Fails:   never.
    Feeds:   fake_grants, fake_pending (a grant change's thing)."""
    return state.data.setdefault("grants", [dict(g) for g in SAMPLE_GRANTS])


def _summary(g, names=False):
    """Purpose: A grant as GET /v1/domain/grants lists it, or (names) as GET /v1/domain/grants/<name> shows it.
    Inputs:  g — a stored grant; names — bool.
    Returns: dict in grants_tool's shape.
    Fails:   never.
    Feeds:   fake_grants, fake_pending."""
    out = {k: g[k] for k in ("name", *FIELDS)}
    people, machines, where_people = g.get("_people", []), g.get("_machines", []), g.get("_where_people", [])
    out.update(reaches_nobody=not people or not (machines or where_people),
               counts={"people": len(people), "machines": len(machines), "where_people": len(where_people)})
    if names:
        out.update(who_people=list(people), where_machines=list(machines), where_people_names=list(where_people),
                   sets=[1] if machines and g["kind"] == "allow" else [],
                   groups=[f"grant-{g['name']}-who", f"grant-{g['name']}-where"],
                   sudo_rule=f"grant-{g['name']}" if g["sudo"] and g["kind"] == "allow" else "")
    return out


def _checked(fields):
    """Purpose: A grant's fields as the DC checks them (check_grant), with its refusals' words.
    Inputs:  fields — the grant's whole fields with its name.
    Returns: the fields.
    Fails:   ValidationError.
    Feeds:   fake_grants."""
    if not re.match(r"^[a-z][a-z0-9-]{1,39}$", fields["name"]) or fields["name"] in ("explain", "sync"):
        raise ValidationError("a grant's name: 2-40 characters, a-z 0-9 -, starting with a letter (not explain or "
                              "sync)")
    for key in ("who", "where"):
        if not fields[key]:
            raise ValidationError(f"{key}: at least one group")
        tier = [n for n in fields[key] if n in TIERS]
        if tier:
            raise ValidationError(f"{key}: {', '.join(tier)} is one of the tiers' groups (2.1.6.66): no grant names it")
    for key, allowed in (("people", PEOPLE_RIGHTS), ("machines", MACHINE_RIGHTS), ("signin", SIGNIN_RIGHTS)):
        bad = [r for r in fields[key] if r not in allowed]
        if bad:
            raise ValidationError(f"{key}: {', '.join(bad)} is not one of {', '.join(allowed)}")
    if "ALL" in fields["sudo"] and "Domain Users" in fields["who"]:
        raise ValidationError("sudo of every command for everyone is refused")
    return fields


def fake_grants(state, who, route, body):
    """Purpose: The fake agent's grants (manual 1.6.13.7): GET /v1/domain/grants, /<name> and /explain/<person>; POST
             /v1/domain/grants, /<name> and /<name>/delete — in memory, refused as the DC refuses.
    Inputs:  state — DevState; who — {"user", "perms"}; route — segments after /v1/; body — dict, or None for a read.
    Returns: the agent's answer, or None for another route.
    Fails:   ValidationError with the DC's reasons.
    Feeds:   fake_agent."""
    if route[:2] != ["domain", "grants"]:
        return None
    grants, rest = _grants(state), route[2:]
    find = lambda name: next((g for g in grants if g["name"] == name), None)    # noqa: E731
    if body is None:
        if not rest:
            return {"grants": [_summary(g) for g in grants], "templates": TEMPLATES}
        if rest[0] == "explain" and len(rest) == 2:
            uid = rest[1]
            if not any(u["uid"] == uid for u in state.data["people"]["users"]):
                raise ValidationError(f"no person {uid} in the domain")
            return {"person": uid, "machine": None, "never": "", "on_machine": None,
                    "grants": [{"name": g["name"], "kind": g["kind"], "reaches": uid in g.get("_people", []),
                                "who_missing": [] if uid in g.get("_people", []) else list(g["who"]),
                                "rights": {k: g[k] for k in ("people", "machines", "signin", "sudo", "local_admin")}}
                               for g in grants]}
        if len(rest) == 1:
            g = find(rest[0])
            if g is None:
                raise ValidationError(f"no grant {rest[0]}")
            return _summary(g, names=True)
        return None
    if not rest:
        name = str(body.get("name") or "")
        if find(name):
            raise ValidationError(f"a grant {name} exists: change it with set")
        template = body.get("template") or ""
        if template and template not in TEMPLATES:
            raise ValidationError(f"no template {template} (templates: {', '.join(TEMPLATES)})")
        given = {k: v for k, v in body.items() if k in FIELDS}
        new = _checked({**FIELDS, **TEMPLATES.get(template, {}), **given, "name": name})
        grants.append({**new, "_people": [], "_machines": []})
        state.log("GRANT_ADD", f"{name} (dev preview: in memory)")
        return {"grant": {k: new[k] for k in ("name", *FIELDS)}, "changed": [f"grant-{name}-who (dev preview)"]}
    g = find(rest[0])
    if g is None:
        raise ValidationError(f"no grant {rest[0]}")
    if rest[1:] == ["delete"]:
        grants.remove(g)
        state.log("GRANT_REMOVE", f"{g['name']} (dev preview: in memory)")
        return {"name": g["name"], "changed": [f"grant-{g['name']}-who removed (dev preview)"]}
    if len(rest) == 1:
        given = {k: v for k, v in body.items() if k in FIELDS}
        if "kind" in given and given["kind"] != g["kind"]:
            raise ValidationError("a grant's kind (allow or restrict) is kept: remove it and add it again")
        g.update(_checked({**{k: g[k] for k in ("name", *FIELDS)}, **given}))
        state.log("GRANT_SET", f"{g['name']} (dev preview: in memory)")
        return {"grant": {k: g[k] for k in ("name", *FIELDS)}, "changed": []}
    return None
