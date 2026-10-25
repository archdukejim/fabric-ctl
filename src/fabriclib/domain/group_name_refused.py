import re

from fabriclib.directory.person_name_refused import DC_RE, FABRIC_GROUPS, FABRIC_PREFIXES, RESERVED
from fabriclib.breakglass.constants import ENTERPRISE_ADMIN

GROUP_RE = re.compile(r"^[a-z][a-z0-9._-]{1,63}$")
AD_GROUPS = {"domain users", "domain admins", "domain computers", "domain guests", "enterprise admins",
             "schema admins", "administrators", "users", "guests"}


def group_name_refused(name):
    """Purpose: why an admin's new group may not take a name (manual 1.2.13, 1.6.12.5): the group-name rule, then
             fabric's names (its accounts and groups: `fabric-*`, `site-*`, `machines-*`, `hosts-*`, `rodc-cache-*`,
             the computed `grant-*` and `access-*`, the tiers' groups, the DCs' `dc-NNNN`, `fabric-admin`), the
             system's and AD's own names. A name another account or group of the domain holds is AD's to refuse.
    Inputs:  name — str.
    Returns: None when it may be taken; otherwise why not (str).
    Fails:   never.
    Feeds:   domain/create_group."""
    name = name or ""
    if not GROUP_RE.match(name):
        return "a group's name: 2-64 characters, a-z 0-9 . _ -, starting with a letter"
    if name == ENTERPRISE_ADMIN or name in FABRIC_GROUPS or name.startswith(FABRIC_PREFIXES) or DC_RE.match(name):
        return f"{name} is one of fabric's names (its accounts, groups and domain controllers, manual 1.2.13)"
    if name in RESERVED or name in AD_GROUPS:
        return f"{name} is one of the system's or the domain's own names"
    return None
