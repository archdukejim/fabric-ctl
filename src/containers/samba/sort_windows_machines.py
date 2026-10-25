import ldb

from group_names import type_group
import paths


def sort_windows_machines(samdb, lp, site, skip=()):
    """Purpose: a Windows machine that joined itself lands in OU=machines (AD's default for new computers); file each
             one found there, once, by its operatingSystem (manual 1.6.13.3, 1.6.11.5): a Server edition into
             OU=servers and `machines-servers`, any other into OU=desktops and `machines-desktops`. Only machines
             directly in OU=machines whose operatingSystem names Windows are sorted; those in skip (sorted before)
             never again, so a machine an admin put back stays where they put it.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: the domain's machines);
             skip — objectGUIDs (str) of machines sorted before.
    Returns: [{"name", "guid", "to", "type"}] the machines sorted now.
    Fails:   ldb.LdbError from the search, a move or a membership AD refuses.
    Feeds:   directory_ops (op "sort_windows_machines")."""
    found = samdb.search(base=paths.folder_dn(samdb, "machines"), scope=ldb.SCOPE_ONELEVEL,
                         expression="(&(objectClass=computer)(operatingSystem=Windows*))",
                         attrs=["cn", "objectGUID", "sAMAccountName", "operatingSystem", "memberOf"])
    skip = {g.lower() for g in skip}
    moved = []
    for m in found:
        guid = str(samdb.schema_format_value("objectGUID", m["objectGUID"][0]), "utf-8")
        if guid.lower() in skip:
            continue
        kind = "server" if "server" in str(m["operatingSystem"][0]).lower() else "desktop"
        to = f"CN={m['cn'][0]},{paths.machine_type_dn(samdb, kind)}"
        samdb.rename(str(m.dn), to)
        account = str(m["sAMAccountName"][0])
        if not any(str(g).lower().startswith(f"cn={type_group(kind)},") for g in m.get("memberOf", [])):
            samdb.add_remove_group_members(type_group(kind), [account], add_members_operation=True)
        moved.append({"name": account.rstrip("$").lower(), "guid": guid, "to": to, "type": kind})
    return moved
