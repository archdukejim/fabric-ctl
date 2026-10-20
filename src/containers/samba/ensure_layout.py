import ldb

import paths

# on each of fabric's folders: what it is (1.6.12.2: fabric's own objects are marked, and shown, never changed by hand)
MARK = "fabric: one of the directory's folders, managed by fabric (manual 1.6.13.2)"
# AD's well-known containers for new users and computers (redirusr, redircmp) -> the folder they point at
WELL_KNOWN = {"A9D1CA15768811D1ADED00C04FD8D5CD": "people", "AA312825768811D1ADED00C04FD8D5CD": "machines"}


def _ensure(samdb, dn, object_class="organizationalUnit"):
    """Purpose: an OU (or a container) created when missing, marked as fabric's.
    Inputs:  samdb — SamDB; dn — str; object_class — organizationalUnit or container.
    Returns: list of str, what was created or marked.
    Fails:   ldb.LdbError other than "already exists" (a missing parent, refused).
    Feeds:   ensure_layout."""
    try:
        samdb.add({"dn": dn, "objectClass": object_class, "description": MARK})
        return [dn]
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_ENTRY_ALREADY_EXISTS:
            raise
    have = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["description"])[0]
    if str(have.get("description", [""])[0]) == MARK:
        return []
    samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "description": MARK}, ldb.FLAG_MOD_REPLACE))
    return [f"{dn}: marked as fabric's"]


def ensure_layout(samdb):
    """Purpose: the directory's folders, one set for the whole domain (manual 1.6.13.2; 2.1.6.72, 2.1.6.80): OU=people,
             OU=service-accounts, OU=groups with OU=fabric inside, OU=machines with one OU per machine type,
             OU=fabric-hosts, OU=devices, OU=device-roles, OU=networks, OU=sudoers; fabric's state, CN=fabric,CN=System
             with CN=dcs and CN=grants inside (2.1.6.79; the grants: 1.6.13.4); and AD's default containers for new
             users and computers pointed at OU=people and OU=machines, so what Windows' own tools create lands in
             fabric's folders. AD's own containers are left as they are.
    Inputs:  samdb — SamDB (as the system).
    Returns: list of str, what was created or changed.
    Fails:   ldb.LdbError from an addition or modification AD refuses.
    Feeds:   converge."""
    base = str(samdb.domain_dn())
    done = []
    for name in paths.FOLDERS:
        done += _ensure(samdb, paths.folder_dn(samdb, name))
    done += _ensure(samdb, paths.computed_groups_dn(samdb))
    for kind in paths.MACHINE_TYPES:
        done += _ensure(samdb, paths.machine_type_dn(samdb, kind))
    done += _ensure(samdb, paths.fabric_dn(samdb), "container")
    done += _ensure(samdb, f"CN=dcs,{paths.fabric_dn(samdb)}", "container")
    done += _ensure(samdb, f"CN=grants,{paths.fabric_dn(samdb)}", "container")
    res = samdb.search(base=base, scope=ldb.SCOPE_BASE, attrs=["wellKnownObjects"])
    for value in [str(x) for x in res[0].get("wellKnownObjects", [])]:
        guid = value.split(":")[2]
        if guid not in WELL_KNOWN:
            continue
        target = paths.folder_dn(samdb, WELL_KNOWN[guid])
        if value.split(":", 3)[3].lower() == target.lower():
            continue
        # the value is replaced in one modify, as Windows' redirusr/redircmp do
        samdb.modify_ldif(f"dn: {base}\nchangetype: modify\ndelete: wellKnownObjects\nwellKnownObjects: {value}\n"
                          f"-\nadd: wellKnownObjects\nwellKnownObjects: B:32:{guid}:{target}\n")
        done.append(f"new {WELL_KNOWN[guid]} go to {target}")
    return done
