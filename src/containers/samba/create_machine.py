import re

import ldb

import paths
from site_roles import CLASSES, DEFAULT_CLASS

NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$")


OS_FAMILIES = ("linux", "windows")      # OU=<family>,OU=<class>,OU=machines (manual 1.6.11.5, 2.1.6.36's revision)
UNMANAGED = "fabric: unmanaged (manual 1.6.11.6)"   # on the account: left out of <site>-fabric-machines


def create_machine(samdb, lp, site, name, password, os=None, managed=True, machine_class=None):
    """Purpose: pre-create a machine's computer account in the site's OU=machines with a one-time join password
             (manual 1.6.7.3, S6.2), so the machine joins with `adcli --login-type=computer` and no admin password
             is typed on it; given its OS family, in `OU=<os>,OU=<servers|desktops>,OU=machines` (1.6.11.5; the
             class decides who may sign in remotely, 2.1.7.14's second revision), its class defaulting by OS
             (DEFAULT_CLASS).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; name — the machine's name
             (1–15 lower-case letters, digits, dashes: a NetBIOS name); password — the one-time password; os —
             "linux", "windows" or None; managed — a member of <site>-fabric-machines (1.6.11.6), or, False, marked
             unmanaged on its description; machine_class — "server", "desktop" or None (by its OS; with no OS
             either, OU=machines itself, where a Windows machine is sorted from by sort_windows_machines).
    Returns: {"name", "dn", "class" ("" when in no class OU)}.
    Fails:   ValueError for a name that is not a machine name, an unknown OS family or class; ldb.LdbError
             ERR_ENTRY_ALREADY_EXISTS when the name is taken, ERR_INSUFFICIENT_ACCESS_RIGHTS outside the agent's site.
    Feeds:   directory_ops (op "create_machine")."""
    if not NAME_RE.match(name or ""):
        raise ValueError(f"not a machine name (1-15 letters, digits, dashes): {name}")
    account = name.upper()               # as Windows and adcli name them: Linux clients look for NAME$ in their keytab
    if os is not None and os not in OS_FAMILIES:
        raise ValueError(f"not an OS family ({', '.join(OS_FAMILIES)}): {os}")
    if machine_class is not None and machine_class not in CLASSES:
        raise ValueError(f"not a machine class ({', '.join(CLASSES)}): {machine_class}")
    cls = machine_class or (DEFAULT_CLASS[os] if os else None)
    machines = f"OU=machines,{paths.site_dn(samdb, site)}"
    if cls:
        machines = f"OU={CLASSES[cls]},{machines}"
    if os:
        machines = f"OU={os},{machines}"
    samdb.newcomputer(account, computerou=paths.relative(samdb, machines))
    samdb.setpassword(f"(sAMAccountName={account}$)", password, force_change_at_next_login=False)
    if managed:
        samdb.add_remove_group_members(f"{site}-fabric-machines", [f"{account}$"], add_members_operation=True)
    else:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": f"CN={account},{machines}", "description": UNMANAGED},
                                           ldb.FLAG_MOD_REPLACE))
    return {"name": name, "dn": f"CN={account},{machines}", "class": cls or ""}
