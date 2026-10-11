import ldb

from host_groups import find_host_group, host_group_name
from paths import site_dn
from refresh_sudo_hosts import refresh_sudo_hosts


def set_host_group_member(samdb, lp, site, name, machine, member):
    """Purpose: a machine of the site put in one of its host groups, or taken out (manual 1.6.11.7); then every sudo
             rule of fabric's editor on a host group names that group's machines again (refresh_sudo_hosts).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; name — the host group's short
             name; machine — the machine's host name; member — bool: in (True) or out.
    Returns: {"group": the AD name, "machine", "member", "changed" (bool), "rules": what the refresh changed}.
    Fails:   ValueError "no host group …", "no machine <machine> in site <site>"; ldb.LdbError
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "set_host_group_member")."""
    full = host_group_name(site, name)
    group = find_host_group(samdb, site, full)
    found = samdb.search(base=f"OU=machines,{site_dn(samdb, site)}", scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                         expression=f"(&(objectCategory=computer)(sAMAccountName={ldb.binary_encode(machine)}$))")
    if not found:
        raise ValueError(f"no machine {machine} in site {site}")
    dn = str(found[0].dn)
    has = dn.lower() in (str(m).lower() for m in group.get("member", []))
    changed = has != bool(member)
    if changed:
        msg = ldb.Message(group.dn)
        msg["member"] = ldb.MessageElement([dn], ldb.FLAG_MOD_ADD if member else ldb.FLAG_MOD_DELETE, "member")
        samdb.modify(msg)
    return {"group": full, "machine": machine, "member": bool(member), "changed": changed,
            "rules": refresh_sudo_hosts(samdb, site)}
