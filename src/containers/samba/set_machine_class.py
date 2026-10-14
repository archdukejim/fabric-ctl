import ldb

import paths
from find_machine import find_machine
from site_roles import CLASSES, class_of


def set_machine_class(samdb, lp, site, name, machine_class):
    """Purpose: change a machine's class (2.1.6.36 as revised 2026-10-13, manual 1.6.11.5): move its account into
             `OU=<linux|windows>,OU=<servers|desktops>,OU=machines` of its site, so the class's log-on GPO, and with
             it `<site>-<class>-remote-users`, decides who may sign in to it remotely (2.1.7.14's second revision).
             Its OS family is kept: the OS OU it sits in, else its operatingSystem (Windows…, else Linux). A second
             call with the same class changes nothing. The site's fabric host is refused: it has a policy of its own
             (2.1.6.53).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; name — the host name (any
             case); machine_class — "server" or "desktop".
    Returns: {"name", "class", "dn" (where it is now), "changed" (bool)}.
    Fails:   ValueError for an unknown class, or the site's fabric host (kind "invalid"); ldb.LdbError
             ERR_NO_SUCH_OBJECT (not a machine of this site, or the class OU not converged yet),
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "set_machine_class") <- fabriclib/directory/set_machine_class."""
    if machine_class not in CLASSES:
        raise ValueError(f"not a machine class ({', '.join(CLASSES)}): {machine_class}")
    site_dn = paths.site_dn(samdb, site)
    m = find_machine(samdb, site, name)
    dn = str(m.dn)
    parts = [p.strip() for p in dn.split(",")]
    if parts[1].lower() == "ou=fabric-hosts":
        raise ValueError(f"{name} is this site's fabric host: it has a log-on policy of its own (2.1.6.53), no class")
    if class_of(dn) == machine_class:
        return {"name": name.lower(), "class": machine_class, "dn": dn, "changed": False}
    if parts[1].lower() in ("ou=linux", "ou=windows"):
        family = parts[1][3:].lower()
    else:
        found = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["operatingSystem"])[0]
        family = "windows" if str(found.get("operatingSystem", idx=0) or "").lower().startswith("windows") \
            else "linux"
    target = f"{parts[0]},OU={family},OU={CLASSES[machine_class]},OU=machines,{site_dn}"
    samdb.rename(dn, target)
    return {"name": name.lower(), "class": machine_class, "dn": target, "changed": True}
