import ldb

from find_gpo import find_gpo


def order_gpo_links(samdb, link_dn, name):
    """Purpose: one GPO's link put first in an OU's `gPLink` string, the others kept in their order after it: the
             lowest precedence there, since Windows and sssd take a right whole from the applicable GPO last in the
             string (2.3.6.19.1). So every set of machines' GPO overrides the fallback (2.1.6.87, manual 1.6.13.4).
    Inputs:  samdb — SamDB (as the system); link_dn — the OU (OU=machines); name — the GPO's display name.
    Returns: list of str, what changed ([] when it already was first, or is not linked there).
    Fails:   ldb.LdbError from AD.
    Feeds:   compile_grants."""
    found = find_gpo(samdb, name)
    if found is None:
        return []
    prefix = f"ldap://{found[0].lower()};"
    current = str(samdb.search(base=link_dn, scope=ldb.SCOPE_BASE, attrs=["gPLink"])[0].get("gPLink", [""])[0])
    parts = [p for p in current.strip("[]").split("][") if p]
    mine = [p for p in parts if p.lower().startswith(prefix)]
    if not mine or parts[0] == mine[0]:
        return []
    ordered = mine[:1] + [p for p in parts if not p.lower().startswith(prefix)]
    samdb.modify(ldb.Message.from_dict(samdb, {"dn": link_dn, "gPLink": "".join(f"[{p}]" for p in ordered)},
                                       ldb.FLAG_MOD_REPLACE))
    return [f"GPO {name}: its link first at {link_dn} (the lowest precedence)"]
