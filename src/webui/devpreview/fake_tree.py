import urllib.parse

from webui.devpreview.fabric_rules import ValidationError
from webui.devpreview.fake_groups import _groups
from webui.devpreview.fake_ous import _tree, kinds_of, place_in
from webui.devpreview.sample_data import SAMPLE_DOMAIN

CONTAINERS = ("Builtin", "Computers", "Users")      # AD's own, shown at the domain's root as RSAT does
COMPUTED = "groups/fabric"                          # the grants' computed groups' OU (1.8.8.3)


def _contents(state, path, internal):
    """Purpose: The preview's objects directly in one OU.
    Inputs:  state — DevState; path — the OU's path; internal — bool, the computed groups shown.
    Returns: list of rows as the DC's browse_ou gives them.
    Fails:   never.
    Feeds:   fake_tree."""
    tree = _tree(state)
    rows = [{"kind": "ou", "name": p.rpartition("/")[2], "dn": "", "at": path, "description": "",
             "disabled": False} for p in tree if p.rpartition("/")[0] == path and (internal or p != COMPUTED)]
    if not path:
        rows += [{"kind": "container", "name": c, "dn": "", "at": "", "description": "AD's own container",
                  "disabled": False} for c in CONTAINERS]
    rows += [{"kind": "person", "name": u["uid"], "dn": "", "at": path, "description": u.get("name", ""),
              "disabled": u.get("state") == "disabled"}
             for u in state.data["people"]["users"] if u.get("ou", "people") == path]
    rows += [{"kind": "group", "name": g["name"], "dn": "", "at": path, "description": g.get("description", ""),
              "disabled": False} for g in _groups(state)
             if g.get("ou", COMPUTED if g["kind"] == "computed" else "groups") == path
             and (internal or g["kind"] != "computed")]
    rows += [{"kind": "machine", "name": m["name"], "dn": "", "at": path, "description": m.get("os", ""),
              "disabled": not m.get("enabled", True)} for m in SAMPLE_DOMAIN["machines"] if m.get("folder") == path]
    return rows


def fake_tree(state, who, route, body):
    """Purpose: The dev preview's directory browser (1.8.8.4): GET directory/tree/ou=…/q=…/w=…/i=… from the sample
             OUs, people, groups and computers; POST people/<uid>/move and groups/<name>/move (Move to..., 1.8.8.5),
             checked as the DC checks them (place_in).
    Inputs:  state — DevState; who — {"user", "perms"}; route — segments after /v1/; body — dict, or None for a read.
    Returns: the agent's answer, or None for another route.
    Fails:   ValidationError with the DC's words (no OU, where it may not go, nobody of that name).
    Feeds:   fake_agent."""
    if body is None and len(route) == 6 and route[:2] == ["directory", "tree"]:
        values = dict(urllib.parse.unquote(s).split("=", 1) for s in route[2:] if "=" in s)
        ou, q = values.get("ou", "").strip("/"), values.get("q", "").strip()
        whole, internal = values.get("w") == "1", values.get("i") == "1"
        tree = _tree(state)
        if ou and ou not in tree:
            raise ValidationError(f"no OU {ou}")
        parts = [p for p in ou.split("/") if p]
        levels = []
        for depth in range(len(parts) + 1):
            at = "/".join(parts[:depth])
            kids = [{"name": p.rpartition("/")[2], "path": p, "kind": "ou", "fabric": tree[p]["fabric"],
                     "kinds": kinds_of(p)} for p in tree if p.rpartition("/")[0] == at and (internal or p != COMPUTED)]
            if not at:
                kids += [{"name": c, "path": c, "kind": "container", "fabric": False, "kinds": []} for c in CONTAINERS]
            levels.append({"path": at, "children": sorted(kids, key=lambda k: k["name"].lower())})
        if whole:
            if len(q) < 2:
                raise ValidationError("a search of the whole domain needs at least 2 characters")
            rows = [r for p in [""] + list(tree) for r in _contents(state, p, internal) if r["kind"] != "container"
                    and (q.lower() in r["name"].lower() or q.lower() in r["description"].lower())]
        else:
            rows = [r for r in _contents(state, ou, internal)
                    if not q or q.lower() in r["name"].lower() or q.lower() in r["description"].lower()]
        return {"ou": ou, "levels": levels, "contents": rows, "found": False, "kinds": kinds_of(ou) if ou else []}
    if body is not None and len(route) == 3 and route[2] == "move" and route[0] in ("people", "groups"):
        kind = "person" if route[0] == "people" else "group"
        path = place_in(state, kind, str(body.get("path") or ""))
        items = state.data["people"]["users"] if kind == "person" else _groups(state)
        key = "uid" if kind == "person" else "name"
        item = next((x for x in items if x[key] == route[1]), None)
        if item is None:
            raise ValidationError(f"no {kind} {route[1]}")
        if kind == "group" and item["kind"] not in ("own", "site"):
            raise ValidationError(f"{route[1]} is one of fabric's {item['kind']} groups: it stays where fabric put it "
                                  "(manual 1.8.8.5)")
        default = "people" if kind == "person" else "groups"
        changed, item["ou"] = item.get("ou", default) != path, path
        return {"kind": kind, "name": route[1], "path": path, "changed": changed}
    return None
