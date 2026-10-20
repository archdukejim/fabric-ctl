"""The grants inside the DC (manual 1.6.13.4 to 1.6.13.7), run as root on its own database and SYSVOL (no credentials,
no network) by fabriclib/grants/grant_request:
    docker exec -i samba python3 /fabric/grants_tool.py < request.json
The request on stdin: {"op": "list"|"show"|"add"|"set"|"remove"|"compile"|"explain"|"authorize"|"managed", "dc" (the DC
asking, dc-NNNN),
"writable_root" (bool: this is the root's writable DC, where grants are changed and compiled), …}. Prints one JSON
object: {"result": …} or {"error": message} (exit 0 either way)."""
import json
import sys

from authorize_action import authorize_action
from check_grant import check_grant
from compile_grants import compile_grants
from ensure_grant_sudo import rule_name
from explain_grants import explain_grants
from grant_members import excluded, reach
from grant_names import FIELDS, TEMPLATES, where_group, who_group
from managed_groups import managed_groups
from grant_store import delete_grant, read_grant, read_grants, read_state, write_grant
from open_samdb import open_samdb

CONF = "/data/etc/smb.conf"
ROOT_ONLY = ("grants are changed and compiled at the root site's writable DC (manual 1.6.13.4): run it on the root's "
             "fabric host")


def _summary(grant, r, sets=None):
    """Purpose: a grant as listed: its fields and whom it reaches, as counts, or as names with `sets`.
    Inputs:  grant — a stored grant; r — reach()'s result for it; sets — the set numbers it is part of, or None (a
             list's row: counts only).
    Returns: dict.
    Fails:   never.
    Feeds:   run."""
    out = {**grant, "reaches_nobody": not r["who"] or not (r["where_computers"] or r["where_people"]),
           "counts": {"people": len(r["who"]), "machines": len(r["where_computers"]),
                      "where_people": len(r["where_people"])}}
    if sets is not None:
        out.update({"who_people": sorted(r["who"].values()),
                    "where_machines": sorted(n.rstrip("$").lower() for n in r["where_computers"].values()),
                    "where_people_names": sorted(r["where_people"].values()), "sets": sets,
                    "groups": [who_group(grant["name"]), where_group(grant["name"])],
                    "sudo_rule": rule_name(grant["name"]) if grant["kind"] == "allow" and grant["sudo"] else ""})
    return out


def _fields(given):
    """Purpose: the grant fields of a request, nothing else.
    Inputs:  given — dict.
    Returns: dict with only FIELDS' keys.
    Fails:   ValueError when it is not an object.
    Feeds:   run."""
    if not isinstance(given, dict):
        raise ValueError("a grant's fields: an object")
    return {k: v for k, v in given.items() if k in FIELDS}


def run(req):
    """Purpose: one grants operation. Reads work at any DC; changes only at the root's writable DC, each followed by a
             compile, so what is stored is at once what AD, sssd and Windows enforce.
    Inputs:  req — {"op", "dc", "writable_root", and per op: "name" (show, add, set, remove), "fields" (add, set: any
             of FIELDS' keys), "template" (add, optional: a TEMPLATES name whose rights fill what fields leave out),
             "person", "machine" (explain), "caller", "action", "target", "bundles" (authorize: fabric-agent's check of
             a call, authorize_action), "user" (managed: the groups they manage)}.
    Returns: list: {"grants": [summaries], "templates": TEMPLATES}; show: one summary with names; add, set: {"grant",
             "changed"}; remove: {"name", "changed"}; compile: {"changed"}; explain: explain_grants' result; authorize:
             authorize_action's;
             managed: managed_groups'.
    Fails:   ValueError for a request refused (its message is shown); ldb.LdbError, OSError.
    Feeds:   this script's main."""
    samdb, lp = open_samdb(CONF)
    op = req.get("op")
    if op in ("list", "show"):
        out = excluded(samdb)
        state, cache = read_state(samdb), {}
        if op == "list":
            return {"grants": [_summary(g, reach(samdb, g, out, cache)) for g in read_grants(samdb)],
                    "templates": TEMPLATES}
        grant = read_grant(samdb, str(req.get("name", "")))
        if grant is None:
            raise ValueError(f"no grant {req.get('name')}")
        sets = sorted(int(n) for n, s in state["sets"].items() if grant["name"] in s["allow"] + s["restrict"])
        return _summary(grant, reach(samdb, grant, out, cache), sets)
    if op == "explain":
        return explain_grants(samdb, str(req.get("person", "")), req.get("machine") or None)
    if op == "managed":                      # the groups a person manages (1.8.6.6): a read, at any DC
        return managed_groups(samdb, str(req.get("user", "")))
    if op == "authorize":                    # fabric-agent's check of a call (1.6.12.2): a read, at any DC
        caller = req.get("caller")
        return authorize_action(samdb, str(caller) if caller is not None else None, str(req.get("action", "")),
                                req.get("target") or {}, [str(b) for b in req.get("bundles") or []])
    if op not in ("add", "set", "remove", "compile"):
        raise ValueError(f"unknown operation {op}")
    if not req.get("writable_root"):
        raise ValueError(ROOT_ONLY)
    dc = req["dc"]
    if op == "compile":
        return {"changed": compile_grants(samdb, lp, dc, bool(req.get("fallback_open")))}
    name = str(req.get("name", ""))
    if op == "remove":
        delete_grant(samdb, name)
        return {"name": name, "changed": compile_grants(samdb, lp, dc, bool(req.get("fallback_open")))}
    fields = _fields(req.get("fields") or {})
    if op == "add":
        if read_grant(samdb, name) is not None:
            raise ValueError(f"a grant {name} exists: change it with set")
        template = req.get("template")
        if template:
            if template not in TEMPLATES:
                raise ValueError(f"no template {template} (templates: {', '.join(TEMPLATES)})")
            fields = {**{k: v for k, v in TEMPLATES[template].items() if k in FIELDS}, **fields}
        grant = check_grant(samdb, {**fields, "name": name})
    else:
        have = read_grant(samdb, name)
        if have is None:
            raise ValueError(f"no grant {name}")
        if "kind" in fields and fields["kind"] != have["kind"]:
            raise ValueError("a grant's kind (allow or restrict) is kept: remove it and add it again")
        grant = check_grant(samdb, {**have, **fields, "name": name})
    write_grant(samdb, grant)
    return {"grant": grant, "changed": compile_grants(samdb, lp, dc, bool(req.get("fallback_open")))}


if __name__ == "__main__":
    try:
        print(json.dumps({"result": run(json.load(sys.stdin))}))
    except ValueError as e:                  # the grants' own refusals: shown as they are
        print(json.dumps({"error": str(e)}))
    except Exception as e:                   # anything else: its kind, for the log
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
