import ldb

import paths


def sort_windows_machines(samdb, lp, site, skip=()):
    """Purpose: a Windows machine that joined itself lands in the site's OU=machines (AD's default for new computers);
             move each one found there, once, into OU=windows (manual 1.6.11.5, 2.1.6.36). Only machines directly
             in OU=machines whose operatingSystem names Windows are moved; those in skip (moved before) never again,
             so a machine an admin put back stays where they put it.
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; skip — objectGUIDs (str) of
             machines moved before.
    Returns: [{"name", "guid", "to"}] the machines moved now.
    Fails:   ldb.LdbError from the search or a move AD refuses.
    Feeds:   directory_ops (op "sort_windows_machines")."""
    machines = f"OU=machines,{paths.site_dn(samdb, site)}"
    found = samdb.search(base=machines, scope=ldb.SCOPE_ONELEVEL,
                         expression="(&(objectClass=computer)(operatingSystem=Windows*))",
                         attrs=["cn", "objectGUID", "sAMAccountName"])
    skip = {g.lower() for g in skip}
    moved = []
    for m in found:
        guid = str(samdb.schema_format_value("objectGUID", m["objectGUID"][0]), "utf-8")
        if guid.lower() in skip:
            continue
        to = f"CN={m['cn'][0]},OU=windows,{machines}"
        samdb.rename(str(m.dn), to)
        moved.append({"name": str(m["sAMAccountName"][0]).rstrip("$").lower(), "guid": guid, "to": to})
    return moved
