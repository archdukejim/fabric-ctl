import ldb

from find_gpo import find_gpo


def unlink_gpo(samdb, link_dn, name):
    """Purpose: one GPO's link taken out of an OU's `gPLink`, the other links kept in their order: fabric's access GPOs
             and the fallback linked at OU=machines before 0.9.1, now at the domain's root (2.1.6.98). Acts only on
             positive evidence: the link is there, naming that GPO.
    Inputs:  samdb — SamDB (as the system); link_dn — the OU (OU=machines); name — the GPO's display name.
    Returns: list of str, what changed ([] when the GPO does not exist or is not linked there).
    Fails:   ldb.LdbError from AD (an OU that does not exist among them).
    Feeds:   compile_grants."""
    found = find_gpo(samdb, name)
    if found is None:
        return []
    prefix = f"ldap://{found[0].lower()};"
    current = str(samdb.search(base=link_dn, scope=ldb.SCOPE_BASE, attrs=["gPLink"])[0].get("gPLink", [""])[0])
    parts = [p for p in current.strip("[]").split("][") if p]
    kept = [p for p in parts if not p.lower().startswith(prefix)]
    if len(kept) == len(parts):
        return []
    value = "".join(f"[{p}]" for p in kept)
    msg = ldb.Message(ldb.Dn(samdb, link_dn))
    msg["gPLink"] = ldb.MessageElement([value] if value else [], ldb.FLAG_MOD_REPLACE, "gPLink")
    samdb.modify(msg)
    return [f"GPO {name}: its link at {link_dn} removed (linked at the domain's root, 2.1.6.98)"]
