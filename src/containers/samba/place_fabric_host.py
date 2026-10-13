import ldb

import paths
from find_machine import find_machine

# on the host's account: what it is, in place of the unmanaged mark it was made with (manual 1.6.11.11)
FABRIC_HOST = "fabric: this site's fabric host, managed by fabric (manual 1.6.11.11)"


def place_fabric_host(samdb, lp, site, name):
    """Purpose: make a computer account of the site its fabric host (decision 2.1.6.49, manual 1.6.11.11): moved into
             the site's OU=fabric-hosts (from OU=machines or below, where setup makes it), a member of
             <site>-fabric-machines, its description saying what it is (the unmanaged mark replaced). Asked once per
             account by the host's setup, which records it, so an admin's later move or removal from the group is
             kept; a second call changes nothing.
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; name — the host's account name
             without its $ (any case).
    Returns: {"name", "dn" (where it is now), "moved": bool, "joined": bool (made a member of the group now)}.
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
    joined = not any(str(g).lower().startswith(f"cn={group.lower()},") for g in found.get("memberOf", []))
    if joined:
        samdb.add_remove_group_members(group, [str(found["sAMAccountName"][0])], add_members_operation=True)
    if str(found.get("description", [""])[0]) != FABRIC_HOST:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": target, "description": FABRIC_HOST}, ldb.FLAG_MOD_REPLACE))
    return {"name": name.lower(), "dn": target, "moved": moved, "joined": joined}
