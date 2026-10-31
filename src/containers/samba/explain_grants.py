import ldb

from grant_members import excluded, reach
from grant_names import gpo_rights
from grant_store import read_grants


def _account(samdb, name, computer):
    """Purpose: a person's or a computer's DN by its name.
    Inputs:  samdb — SamDB; name — a user name, or a computer's short name; computer — bool.
    Returns: dn str (lower case).
    Fails:   ValueError "no person <name>" / "no machine <name>"; ldb.LdbError from the search.
    Feeds:   explain_grants."""
    account = name.rstrip("$") + "$" if computer else name
    kind = "(objectClass=computer)" if computer else "(&(objectClass=user)(!(objectClass=computer)))"
    found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                         expression=f"(&{kind}(sAMAccountName={ldb.binary_encode(account)}))")
    if not found:
        raise ValueError(f"no {'machine' if computer else 'person'} {name} in the domain")
    return str(found[0].dn).lower()


def explain_grants(samdb, person, machine=None):
    """Purpose: which grants reach a person, and on a machine, and why (manual 1.6.13.7): for each grant whether the
             person is in all its who groups (those missing named) and, with a machine, whether the machine is in all
             its where groups; the person's sign-in, local administrator and sudo there, as the compiled sets give them
             (allowing grants, narrowed by restricting ones, 2.1.6.77; a machine no allowing grant reaches admits nobody
             from the domain, 2.1.6.87). Read from the directory as it is, not from the last compile.
    Inputs:  samdb — SamDB; person — a user name; machine — a computer's short name, or None.
    Returns: {"person", "machine", "never" (why no grant reaches the person, or ""), "grants": [{"name", "kind",
             "who_missing": [groups], "where_missing": [groups] (with a machine), "reaches": bool, "rights": {people,
             machines, signin, sudo, local_admin}}], "on_machine": {"keyboard", "remote", "local-admin": bool, "sudo":
             [commands]} (with a machine; None without)}.
    Fails:   ValueError for a person or machine not in the domain; ldb.LdbError.
    Feeds:   grants_tool (op "explain")."""
    pdn = _account(samdb, person, False)
    mdn = _account(samdb, machine, True) if machine else None
    out = excluded(samdb)
    never = ""
    if pdn in out["top"]:
        never = "in AD's top tier or one of fabric's own accounts: no grant reaches them (2.1.6.66)"
    cache, rows, reached = {}, [], {}
    for g in read_grants(samdb):
        reached[g["name"]] = r = reach(samdb, g, out, cache)
        who_missing = [n for n in g["who"] if pdn not in cache[n]["people"]]
        row = {"name": g["name"], "kind": g["kind"], "who_missing": who_missing,
               "rights": {k: g[k] for k in ("people", "machines", "signin", "sudo", "local_admin")}}
        if mdn:
            row["where_missing"] = [n for n in g["where"] if mdn not in cache[n]["computers"]]
            row["reaches"] = pdn in r["who"] and mdn in r["where_computers"]
        else:
            row["reaches"] = pdn in r["who"]
        rows.append(row)
    on = None
    if mdn:
        on = {"keyboard": False, "remote": False, "local-admin": False, "sudo": []}
        grants = {g["name"]: g for g in read_grants(samdb)}
        here = [n for n in grants if mdn in reached[n]["where_computers"]]
        allow = [n for n in here if grants[n]["kind"] == "allow"]
        restrict = [n for n in here if grants[n]["kind"] == "restrict"]
        if any(gpo_rights(grants[n]) for n in allow):
            for right in on:
                if right == "sudo":
                    continue
                holders = [n for n in allow if right in gpo_rights(grants[n])]
                narrowing = [n for n in restrict if right in gpo_rights(grants[n])]
                on[right] = any(pdn in reached[n]["who"] for n in holders) \
                    and all(pdn in reached[n]["who"] for n in narrowing)
        for n in allow:
            if grants[n]["sudo"] and pdn in reached[n]["who"]:
                on["sudo"] += grants[n]["sudo"]
    return {"person": person, "machine": machine, "never": never, "grants": rows, "on_machine": on}
