import ldb

from find_machine import MACHINE_OUS
from paths import site_dn
from site_roles import rodc_cache

# the site's people groups nested in its cache group: their members are cached through it (2.1.6.55)
PEOPLE_GROUPS = ("users", "admins")


def _group_dn(samdb, name):
    """Purpose: a group's DN by its name, anywhere in the domain.
    Inputs:  samdb — SamDB; name — sAMAccountName.
    Returns: str.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT when there is no such group (the site has not converged).
    Feeds:   sync_rodc_cache."""
    res = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                       expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))", attrs=["dn"])
    if not res:
        raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT, f"no group {name}")
    return str(res[0].dn)


def _machines(samdb, base):
    """Purpose: the DNs of the site's computer accounts: its OU=machines (and the OUs below) and its OU=fabric-hosts.
    Inputs:  samdb — SamDB; base — the site's OU.
    Returns: list of str.
    Fails:   ldb.LdbError from a search (an OU not converged yet holds nothing).
    Feeds:   sync_rodc_cache."""
    out = []
    for ou in MACHINE_OUS:
        try:
            out += [str(m.dn) for m in samdb.search(base=f"OU={ou},{base}", scope=ldb.SCOPE_SUBTREE,
                                                    expression="(objectCategory=computer)", attrs=["dn"])]
        except ldb.LdbError as e:
            if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
                raise
    return out


def _own(dn, base):
    """Purpose: whether an account is one of the site's own: a person in its OU=people (not below: a nested site's
             people are that site's), or a computer in its OU=machines (and below) or OU=fabric-hosts.
    Inputs:  dn — the account's DN; base — the site's OU.
    Returns: bool.
    Fails:   never.
    Feeds:   sync_rodc_cache."""
    low, b = dn.lower(), base.lower()
    if low.endswith(f",ou=people,{b}") and low.count(",") == b.count(",") + 2:
        return True
    return any(low.endswith(f",ou={ou},{b}") for ou in MACHINE_OUS)


def _accounts(samdb, group):
    """Purpose: every account a group reaches, through the groups nested in it (each group read once).
    Inputs:  samdb — SamDB; group — the group's DN.
    Returns: list of (account DN, the group it is a direct member of), sorted.
    Fails:   ldb.LdbError from a search.
    Feeds:   sync_rodc_cache."""
    seen, todo, out = set(), [group], []
    while todo:
        g = todo.pop()
        if g.lower() in seen:
            continue
        seen.add(g.lower())
        for m in samdb.search(base=g, scope=ldb.SCOPE_BASE, attrs=["member"])[0].get("member", []):
            found = samdb.search(base=str(m), scope=ldb.SCOPE_BASE, attrs=["objectClass"])[0]
            classes = [str(c).lower() for c in found.get("objectClass", [])]
            if "group" in classes:
                todo.append(str(found.dn))
            elif "user" in classes:              # people and computers (computer derives from user)
                out.append((str(found.dn), g))
    return sorted(set(out))


def sync_rodc_cache(samdb, lp, site):
    """Purpose: keep the site's `<site>-rodc-cache` group (on its read-only DC's password replication allow list,
             2.1.6.52) holding exactly the site's people and machines (decision 2.1.6.55, manual 1.6.11.14): the
             site's `<site>-users` and `<site>-admins` nested in it (Samba's password replication policy reads the
             account's tokenGroups, its transitive membership, so nesting counts), each of the site's computer
             accounts a direct member (no group holds a site's machines), and nothing else: a direct member fabric did
             not put there (a machine that left the site, anything added by hand) is taken out. Run at the writable DC
             as the site's agent; a second run changes nothing.
    Inputs:  samdb — SamDB (as the site's agent, at the writable DC); lp — LoadParm (unused); site — str.
    Returns: {"added": [DN], "removed": [DN] (direct members changed now), "accounts": [DN] (the site's own accounts
             the group reaches: what the read-only DC is asked to preload), "foreign": [[DN, through group DN]]
             (accounts the group reaches that are not the site's own: a person of another site or an organisation
             account nested into the site's groups by hand; never preloaded, reported)}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT (the site's groups not converged yet), ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "sync_rodc_cache")."""
    base = site_dn(samdb, site)
    cache = _group_dn(samdb, rodc_cache(site))
    want = {d.lower(): d for d in [_group_dn(samdb, f"{site}-{g}") for g in PEOPLE_GROUPS] + _machines(samdb, base)}
    have = {str(m).lower(): str(m) for m in samdb.search(base=cache, scope=ldb.SCOPE_BASE,
                                                         attrs=["member"])[0].get("member", [])}
    added = [want[k] for k in sorted(want) if k not in have]
    removed = [have[k] for k in sorted(have) if k not in want]
    for flag, dns in ((ldb.FLAG_MOD_ADD, added), (ldb.FLAG_MOD_DELETE, removed)):
        if dns:
            msg = ldb.Message(ldb.Dn(samdb, cache))
            msg["member"] = ldb.MessageElement(dns, flag, "member")
            samdb.modify(msg)
    accounts, foreign = [], []
    for dn, through in _accounts(samdb, cache):
        if _own(dn, base):
            accounts.append(dn)
        else:
            foreign.append([dn, through])
    return {"added": added, "removed": removed, "accounts": sorted(set(accounts)), "foreign": foreign}
