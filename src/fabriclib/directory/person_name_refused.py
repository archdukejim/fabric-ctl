import re

from fabriclib.breakglass.constants import ENTERPRISE_ADMIN

UID_RE = re.compile(r"^[a-z][a-z0-9._-]{1,31}$")
# the system's own accounts and AD's built-in ones
RESERVED = {"admin", "root", "administrator", "guest", "krbtgt", "nobody", "daemon", "users"}
# the groups fabric makes in the domain (1.6.13.3), which share the account names' namespace in AD
FABRIC_GROUPS = {"directory-admins", "dc-hosts", "server-admins", "desktop-admins", "network-admins"}
FABRIC_PREFIXES = ("fabric-", "site-", "machines-", "hosts-", "rodc-cache-")
DC_RE = re.compile(r"^dc-\d{4}$")


def person_name_refused(uid):
    """Purpose: why a person may not take a user name (manual 1.2.13): it must follow the user-name rule and not be one
             of fabric's names — `fabric-admin` (the Enterprise Admin, 2.1.6.69), fabric's own `fabric-*` accounts,
             the groups fabric makes (`directory-admins`, `dc-hosts`, the tiers', `site-*`, `machines-*`,
             `hosts-*`, `rodc-cache-*`), a DC's name (`dc-NNNN`) — or a system or AD built-in account.
    Inputs:  uid — str.
    Returns: None when it may be taken; otherwise why not (str).
    Fails:   never.
    Feeds:   setup/common/valid_setting (the first Directory Administrator), setup/check_first_admin."""
    uid = uid or ""
    if not UID_RE.match(uid):
        return "a user name: 2-32 characters, a-z 0-9 . _ -, starting with a letter"
    if uid == ENTERPRISE_ADMIN:
        return "fabric-admin is the Enterprise Admin's own account (2.1.6.69): choose your own user name"
    if uid in RESERVED:
        return f"{uid} is one of the system's or the domain's own accounts"
    if uid in FABRIC_GROUPS or uid.startswith(FABRIC_PREFIXES) or DC_RE.match(uid):
        return f"{uid} is one of fabric's names (its accounts, groups and domain controllers, manual 1.2.13)"
    return None
