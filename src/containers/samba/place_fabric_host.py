import ldb

from find_machine import find_machine
from group_names import DC_HOSTS, FABRIC_MANAGED, rodc_cache as cache_group
import paths

# on the host's account: what it is, in place of the unmanaged mark it was made with (manual 1.6.11.11)
FABRIC_HOST = "fabric: a fabric host, which runs a domain controller, managed by fabric (manual 1.6.11.11)"


def _member(found, group):
    """Purpose: whether an account is a member of a group, by its memberOf.
    Inputs:  found — ldb.Message with memberOf; group — the group's name.
    Returns: bool.
    Fails:   never.
    Feeds:   place_fabric_host."""
    return any(str(g).lower().startswith(f"cn={group.lower()},") for g in found.get("memberOf", []))


def place_fabric_host(samdb, lp, site, name, rodc_cache=False, dc=""):
    """Purpose: make a computer account a fabric host (decisions 2.1.6.49, 2.1.6.70; manual 1.6.11.11, 1.6.13.6): moved
             into OU=fabric-hosts (from OU=machines or below, where setup makes it), a member of `fabric-managed` and
             of `dc-hosts`, the hosts that run a DC, its description saying what it is (the unmanaged mark replaced).
             Asked once per account by the host's setup, which records it, so an admin's later move or removal from
             a group is kept; a second call changes nothing.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: a fabric host is in no
             site's group, so no grant on a site reaches it, 1.6.13.6); name — the host's account name without its $
             (any case); rodc_cache — also a member of `rodc-cache-<dc>`, so this DC, a read-only one, may cache its
             password (2.1.6.52, 2.1.6.85; this operation then runs at the writable DC); dc — the host's DC (the
             request's).
    Returns: {"name", "dn" (where it is now), "moved": bool, "joined": [the groups it was made a member of now],
             "cached": bool (made a member of rodc-cache-<dc> now)}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT (no such machine, or no OU=fabric-hosts yet: the domain has not
             converged), ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "place_fabric_host")."""
    m = find_machine(samdb, name)
    dn = str(m.dn)
    target = f"{dn.split(',', 1)[0]},{paths.folder_dn(samdb, 'fabric-hosts')}"
    moved = dn.lower() != target.lower()
    if moved:
        samdb.rename(dn, target)
    found = samdb.search(base=target, scope=ldb.SCOPE_BASE, attrs=["description", "memberOf", "sAMAccountName"])[0]
    account = str(found["sAMAccountName"][0])
    joined = [g for g in (FABRIC_MANAGED, DC_HOSTS) if not _member(found, g)]
    for group in joined:
        samdb.add_remove_group_members(group, [account], add_members_operation=True)
    cached = bool(rodc_cache) and not _member(found, cache_group(dc))
    if cached:
        samdb.add_remove_group_members(cache_group(dc), [account], add_members_operation=True)
    if str(found.get("description", [""])[0]) != FABRIC_HOST:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": target, "description": FABRIC_HOST}, ldb.FLAG_MOD_REPLACE))
    return {"name": name.lower(), "dn": target, "moved": moved, "joined": joined, "cached": cached}
