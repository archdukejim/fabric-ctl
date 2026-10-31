import ldb

from find_machine import find_machine
from grant_members import excluded, reach
from grant_store import read_grants


def reaching_grants(samdb, machine):
    """Purpose: the grants that reach a computer and what each gives there (manual 1.6.12.6, 1.6.13.4): those whose
             where groups all hold it (allowing and restricting alike), read from the directory as it is.
    Inputs:  samdb — SamDB; machine — the computer's host name (any case), in OU=machines or OU=fabric-hosts.
    Returns: {"machine", "grants": [{"name", "kind", "description", "who": [groups], "people": how many the who reaches,
             "rights": {people, machines, signin, sudo, local_admin}}]}, by name.
    Fails:   ValueError "no machine <name> in the domain"; ldb.LdbError from a search.
    Feeds:   grants_tool (op "reaching")."""
    try:
        mdn = str(find_machine(samdb, str(machine or "")).dn).lower()
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
        raise ValueError(f"no machine {machine} in the domain")
    out, cache, rows = excluded(samdb), {}, []
    for g in read_grants(samdb):
        r = reach(samdb, g, out, cache)
        if mdn in {dn.lower() for dn in r["where_computers"]}:
            rows.append({"name": g["name"], "kind": g["kind"], "description": g.get("description", ""),
                         "who": list(g["who"]), "people": len(r["who"]),
                         "rights": {k: g[k] for k in ("people", "machines", "signin", "sudo", "local_admin")}})
    return {"machine": machine, "grants": sorted(rows, key=lambda x: x["name"])}
