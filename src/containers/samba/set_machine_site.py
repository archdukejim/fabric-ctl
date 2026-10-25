import ldb

import paths
from find_machine import find_machine
from group_names import site_group


def set_machine_site(samdb, lp, site, name, site_name, member):
    """Purpose: a computer put in a site, or taken out of one (manual 1.6.12.6, Sites; 2.1.6.72: a site is the group
             `site-<name>` of its people and machines): only one of the domain's sites (its group made by fabric).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the host name;
             site_name — the site; member — bool: in (True) or out.
    Returns: {"name", "site", "member", "changed": bool}.
    Fails:   ValueError "no site <site_name> in the domain", a fabric host; ldb.LdbError ERR_NO_SUCH_OBJECT (no such
             machine), ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "set_machine_site")."""
    group = site_group(site_name)
    found = samdb.search(base=paths.folder_dn(samdb, "groups"), scope=ldb.SCOPE_ONELEVEL, attrs=["member"],
                         expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(group)}))")
    if not found:
        raise ValueError(f"no site {site_name} in the domain (its group {group})")
    m = find_machine(samdb, name)
    if not str(m.dn).lower().endswith("," + paths.folder_dn(samdb, "machines").lower()):
        raise ValueError(f"{name} is a fabric host: managed by fabric (manual 1.6.13.6)")
    inside = str(m.dn).lower() in {str(x).lower() for x in found[0].get("member", [])}
    if inside == bool(member):
        return {"name": name, "site": site_name, "member": bool(member), "changed": False}
    samdb.add_remove_group_members(group, [f"{name.rstrip('$')}$"], add_members_operation=bool(member))
    return {"name": name, "site": site_name, "member": bool(member), "changed": True}
