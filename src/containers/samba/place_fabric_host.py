import ldb

import paths
from find_machine import find_machine
from site_roles import rodc_cache as cache_group

# on the host's account: what it is, in place of the unmanaged mark it was made with (manual 1.6.11.11)
FABRIC_HOST = "fabric: this site's fabric host, managed by fabric (manual 1.6.11.11)"


def _member(found, group):
    """Purpose: whether an account is a member of a group, by its memberOf.
    Inputs:  found — ldb.Message with memberOf; group — the group's name.
    Returns: bool.
    Fails:   never.
    Feeds:   place_fabric_host."""
    return any(str(g).lower().startswith(f"cn={group.lower()},") for g in found.get("memberOf", []))


def place_fabric_host(samdb, lp, site, name, rodc_cache=False):
    """Purpose: make a computer account of the site its fabric host (decision 2.1.6.49, manual 1.6.11.11): moved into
             the site's OU=fabric-hosts (from OU=machines or below, where setup makes it), a member of
             <site>-fabric-machines, its description saying what it is (the unmanaged mark replaced). Asked once per
             account by the host's setup, which records it, so an admin's later move or removal from the group is
             kept; a second call changes nothing.
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; name — the host's account name
             without its $ (any case); rodc_cache — also a member of <site>-rodc-cache, so the site's read-only DC
             may cache its password (2.1.6.52; this operation then runs at the writable DC).
    Returns: {"name", "dn" (where it is now), "moved": bool, "joined": bool (made a member of <site>-fabric-machines
             now), "cached": bool (made a member of <site>-rodc-cache now)}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT (not a machine of this site, or no OU=fabric-hosts yet: the site has not
             converged), ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "place_fabric_host")."""
    m = find_machine(samdb, site, name)
    dn = str(m.dn)
    target = f"{dn.split(',', 1)[0]},OU=fabric-hosts,{paths.site_dn(samdb, site)}"
    moved = dn.lower() != target.lower()
    if moved:
        samdb.rename(dn, target)
    found = samdb.search(base=target, scope=ldb.SCOPE_BASE, attrs=["description", "memberOf", "sAMAccountName"])[0]
    group = f"{site}-fabric-machines"
    account = str(found["sAMAccountName"][0])
    joined = not _member(found, group)
    if joined:
        samdb.add_remove_group_members(group, [account], add_members_operation=True)
    cached = bool(rodc_cache) and not _member(found, cache_group(site))
    if cached:
        samdb.add_remove_group_members(cache_group(site), [account], add_members_operation=True)
    if str(found.get("description", [""])[0]) != FABRIC_HOST:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": target, "description": FABRIC_HOST}, ldb.FLAG_MOD_REPLACE))
    return {"name": name.lower(), "dn": target, "moved": moved, "joined": joined, "cached": cached}
