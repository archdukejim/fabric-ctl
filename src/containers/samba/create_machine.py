import re

import paths

NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$")


OS_FAMILIES = ("linux", "windows")      # OU=<family>,OU=machines (manual 1.6.11.5)


def create_machine(samdb, lp, site, name, password, os=None):
    """Purpose: pre-create a machine's computer account in the site's OU=machines (its OS family's OU when given,
             1.6.11.5) with a one-time join password
             (manual 1.6.7.3, S6.2), so the machine joins with `adcli --login-type=computer` and no admin password
             is typed on it.
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; name — the machine's name
             (1–15 lower-case letters, digits, dashes: a NetBIOS name); password — the one-time password; os —
             "linux", "windows" or None (OU=machines itself).
    Returns: {"name", "dn"}.
    Fails:   ValueError for a name that is not a machine name, or an unknown OS family; ldb.LdbError
             ERR_ENTRY_ALREADY_EXISTS when the name is taken, ERR_INSUFFICIENT_ACCESS_RIGHTS outside the agent's site.
    Feeds:   directory_ops (op "create_machine")."""
    if not NAME_RE.match(name or ""):
        raise ValueError(f"not a machine name (1-15 letters, digits, dashes): {name}")
    account = name.upper()               # as Windows and adcli name them: Linux clients look for NAME$ in their keytab
    if os is not None and os not in OS_FAMILIES:
        raise ValueError(f"not an OS family ({', '.join(OS_FAMILIES)}): {os}")
    machines = f"OU=machines,{paths.site_dn(samdb, site)}"
    if os:
        machines = f"OU={os},{machines}"
    samdb.newcomputer(account, computerou=paths.relative(samdb, machines))
    samdb.setpassword(f"(sAMAccountName={account}$)", password, force_change_at_next_login=False)
    return {"name": name, "dn": f"CN={account},{machines}"}
