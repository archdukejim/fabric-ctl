import ldb

from group_names import FABRIC_MANAGED, site_group
import paths

# what an unmanaged join writes on the account (join-linux.sh --unmanaged; add-machine --unmanaged)
UNMANAGED = "fabric: unmanaged (manual 1.6.11.6)"


def adopt_linux_machines(samdb, lp, site, skip=()):
    """Purpose: a Linux machine joined with an administrator's password lands in its type's OU and its site's group on
             its own (join-linux.sh); make each such machine of this site a member of `fabric-managed`, once (manual
             1.6.11.6, 2.1.6.40): a computer under OU=machines in `site-<site>` whose operatingSystem is not Windows;
             not one marked unmanaged by its join, not one adopted before (an admin who takes a machine out keeps it
             out). One already a member (its join adds it itself since 2.1.6.97) is returned as seen, unchanged, so
             the record keeps it too.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str; skip — objectGUIDs (str) of
             machines adopted or seen before.
    Returns: [{"name", "guid", "seen" (True: a member already, nothing changed)}]: the machines made members now,
             and those seen.
    Fails:   ldb.LdbError from the search or a change AD refuses.
    Feeds:   directory_ops (op "adopt_linux_machines")."""
    groups = paths.folder_dn(samdb, "groups")
    found = samdb.search(base=paths.folder_dn(samdb, "machines"), scope=ldb.SCOPE_SUBTREE,
                         expression=f"(&(objectClass=computer)(operatingSystem=*)(!(operatingSystem=Windows*))"
                                    f"(memberOf=CN={ldb.binary_encode(site_group(site))},{groups}))",
                         attrs=["objectGUID", "sAMAccountName", "description", "memberOf"])
    skip = {g.lower() for g in skip}
    adopted = []
    for m in found:
        guid = str(samdb.schema_format_value("objectGUID", m["objectGUID"][0]), "utf-8")
        if guid.lower() in skip or str(m.get("description", [""])[0]) == UNMANAGED:
            continue
        name = str(m["sAMAccountName"][0]).rstrip("$").lower()
        if any(str(g).lower().startswith(f"cn={FABRIC_MANAGED},") for g in m.get("memberOf", [])):
            adopted.append({"name": name, "guid": guid, "seen": True})
            continue
        samdb.add_remove_group_members(FABRIC_MANAGED, [str(m["sAMAccountName"][0])], add_members_operation=True)
        adopted.append({"name": name, "guid": guid, "seen": False})
    return adopted
