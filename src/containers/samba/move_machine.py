import paths
from find_machine import find_machine
from ou_paths import exists, ou_dn, ou_path


def move_machine(samdb, lp, site, name, path):
    """Purpose: a computer moved to another folder under OU=machines (manual 1.6.12.6, Move to folder): OU=machines
             itself, a type's OU, or an admin's own below them. Its groups stay, so nobody's access changes (OUs grant
             nothing, 2.1.6.72). A fabric host (OU=fabric-hosts) is never moved.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the host name;
             path — the target OU's path ("machines", "machines/servers/web").
    Returns: {"name", "path", "changed": bool}.
    Fails:   ValueError: a target not under OU=machines, no such OU, a machine not in OU=machines; ldb.LdbError
             ERR_NO_SUCH_OBJECT (no such machine), ERR_ENTRY_ALREADY_EXISTS (a namesake there),
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "move_machine")."""
    machines = paths.folder_dn(samdb, "machines").lower()
    target = ou_dn(samdb, path)
    if target.lower() != machines and not target.lower().endswith("," + machines):
        raise ValueError(f"a computer moves only to a folder under OU=machines (not {path}, manual 1.6.12.6)")
    if not exists(samdb, target):
        raise ValueError(f"no OU {path}")
    m = find_machine(samdb, name)
    dn = str(m.dn)
    if not dn.lower().endswith("," + machines):
        raise ValueError(f"{name} is a fabric host: managed by fabric (manual 1.6.13.6)")
    if dn.split(",", 1)[1].lower() == target.lower():
        return {"name": name, "path": ou_path(samdb, target), "changed": False}
    samdb.rename(dn, f"{dn.split(',', 1)[0]},{target}")
    return {"name": name, "path": ou_path(samdb, target), "changed": True}
