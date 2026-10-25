import paths
from find_machine import find_machine
from group_names import type_group


def set_machine_type(samdb, lp, site, name, type, move=False):
    """Purpose: a computer's type changed (manual 1.6.12.6, Change type; 1.6.13.3): it goes into that type's group
             (`machines-servers`, ...) and out of the others', so the grants on its type follow; with move, it is also
             moved to that type's OU (only from OU=machines itself or another type's OU: an admin's own folder is
             kept, said in the answer).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the host name;
             type — server, desktop or network; move — bool.
    Returns: {"name", "type", "changed": [what changed], "kept_folder": the admin's folder kept, or ""}.
    Fails:   ValueError for an unknown type or a fabric host; ldb.LdbError ERR_NO_SUCH_OBJECT (no such machine),
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "set_machine_type")."""
    if type not in paths.MACHINE_TYPES:
        raise ValueError(f"type: one of {', '.join(paths.MACHINE_TYPES)}, not {type!r}")
    m = find_machine(samdb, name)
    dn = str(m.dn)
    machines = paths.folder_dn(samdb, "machines").lower()
    if not dn.lower().endswith("," + machines):
        raise ValueError(f"{name} is a fabric host: managed by fabric (manual 1.6.13.6)")
    account = f"{name.rstrip('$')}$"
    groups = {str(g).split(",", 1)[0].split("=", 1)[1].lower() for g in m.get("memberOf", [])}
    changed, kept = [], ""
    for kind in paths.MACHINE_TYPES:
        group = type_group(kind)
        if kind == type and group not in groups:
            samdb.add_remove_group_members(group, [account], add_members_operation=True)
            changed.append(f"in {group}")
        elif kind != type and group in groups:
            samdb.add_remove_group_members(group, [account], add_members_operation=False)
            changed.append(f"out of {group}")
    if move:
        parent = dn.split(",", 1)[1].lower()
        target = paths.machine_type_dn(samdb, type)
        fabric_ous = {machines} | {paths.machine_type_dn(samdb, k).lower() for k in paths.MACHINE_TYPES}
        if parent == target.lower():
            pass
        elif parent in fabric_ous:
            samdb.rename(dn, f"{dn.split(',', 1)[0]},{target}")
            changed.append(f"moved to {target.split(',', 2)[0]}")
        else:
            kept = parent
    return {"name": name, "type": type, "changed": changed, "kept_folder": kept}
