import re

import ldb

from group_names import FABRIC_MANAGED, site_group, type_group
import paths

NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$")
UNMANAGED = "fabric: unmanaged (manual 1.6.11.6)"   # on the account: left out of fabric-managed


def create_machine(samdb, lp, site, name, password, type=None, managed=True, in_site=True):
    """Purpose: pre-create a machine's computer account (manual 1.6.7.3, S6.2; 1.6.13.3) with a one-time join
             password, so the machine joins with `adcli --login-type=computer` and no admin password is typed on it:
             in its type's OU under OU=machines and its type's group (`machines-servers`, `machines-desktops`,
             `machines-network`) when a type is given, else in OU=machines itself; in its site's group
             (`site-<site>`); in `fabric-managed` (1.6.11.6) unless unmanaged, then marked so on its description.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str; name — the machine's name (1–15
             lower-case letters, digits, dashes: a NetBIOS name); password — the one-time password; type — "server",
             "desktop", "network" or None; managed — bool; in_site — False leaves it out of the site's group (the fabric
             host's own account, which joins dc-hosts instead: place_fabric_host).
    Returns: {"name", "dn"}.
    Fails:   ValueError for a name that is not a machine name, or an unknown type; ldb.LdbError
             ERR_ENTRY_ALREADY_EXISTS when the name is taken, ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "create_machine")."""
    if not NAME_RE.match(name or ""):
        raise ValueError(f"not a machine name (1-15 letters, digits, dashes): {name}")
    account = name.upper()               # as Windows and adcli name them: Linux clients look for NAME$ in their keytab
    where = paths.machine_type_dn(samdb, type) if type is not None else paths.folder_dn(samdb, "machines")
    samdb.newcomputer(account, computerou=paths.relative(samdb, where))
    samdb.setpassword(f"(sAMAccountName={account}$)", password, force_change_at_next_login=False)
    groups = ([type_group(type)] if type is not None else []) + ([site_group(site)] if in_site else []) \
        + ([FABRIC_MANAGED] if managed else [])
    for group in groups:
        samdb.add_remove_group_members(group, [f"{account}$"], add_members_operation=True)
    if not managed:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": f"CN={account},{where}", "description": UNMANAGED},
                                           ldb.FLAG_MOD_REPLACE))
    return {"name": name, "dn": f"CN={account},{where}"}
