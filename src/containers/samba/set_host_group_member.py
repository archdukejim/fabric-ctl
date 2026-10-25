import ldb

from host_groups import find_host_group, host_group_name
import paths
from refresh_sudo_hosts import refresh_sudo_hosts


def set_host_group_member(samdb, lp, site, name, machine, member):
    """Purpose: a machine put in a host group, or taken out (manual 1.6.11.7); then every sudo rule of fabric's editor
             on a host group names that group's machines again (refresh_sudo_hosts). Only machines in OU=machines
             (and below) are put in: never a fabric host, which no domain sudo rule reaches (1.6.13.6).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the host group's
             short name; machine — the machine's host name; member — bool: in (True) or out.
    Returns: {"group": the AD name, "machine", "member", "changed" (bool), "rules": what the refresh changed}.
    Fails:   ValueError "no host group …", "no machine <machine> in OU=machines"; ldb.LdbError
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "set_host_group_member")."""
    full = host_group_name(name)
    group = find_host_group(samdb, full)
    found = samdb.search(base=paths.folder_dn(samdb, "machines"), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                         expression=f"(&(objectCategory=computer)(sAMAccountName={ldb.binary_encode(machine)}$))")
    if not found:
        raise ValueError(f"no machine {machine} in OU=machines")
    dn = str(found[0].dn)
    has = dn.lower() in (str(m).lower() for m in group.get("member", []))
    changed = has != bool(member)
    if changed:
        msg = ldb.Message(group.dn)
        msg["member"] = ldb.MessageElement([dn], ldb.FLAG_MOD_ADD if member else ldb.FLAG_MOD_DELETE, "member")
        samdb.modify(msg)
    return {"group": full, "machine": machine, "member": bool(member), "changed": changed,
            "rules": refresh_sudo_hosts(samdb)}
