import datetime

import ldb

from find_machine import MACHINE_OUS
from paths import site_dn

ACCOUNTDISABLE = 0x2


def _when(filetime):
    """Purpose: an AD timestamp (100 ns since 1601) as ISO text.
    Inputs:  filetime — str or int; "0" or absent for never.
    Returns: str, "" for never.
    Fails:   never (a value that is not a number counts as never).
    Feeds:   list_machines."""
    try:
        value = int(filetime)
    except (TypeError, ValueError):
        return ""
    if value <= 0:
        return ""
    seconds = value / 10_000_000 - 11644473600
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).isoformat(timespec="seconds")


def list_machines(samdb, lp, site):
    """Purpose: the site's machines (manual 1.6.7.6, 1.6.5.21 S7.4): the computer accounts in its OU=machines,
             Windows and Linux alike, and its fabric host in OU=fabric-hosts (1.6.11.11).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str.
    Returns: list of {"name" (the host name, lower case), "dns", "os", "enabled", "last_logon" (ISO or ""),
             "created" (ISO), "dn"}, sorted by name.
    Fails:   ldb.LdbError from the search.
    Feeds:   directory_ops (op "list_machines")."""
    out, found = [], []
    for ou in MACHINE_OUS:
        try:
            found += samdb.search(base=f"OU={ou},{site_dn(samdb, site)}", scope=ldb.SCOPE_SUBTREE,
                                  expression="(objectCategory=computer)",
                                  attrs=["sAMAccountName", "dNSHostName", "operatingSystem", "userAccountControl",
                                         "lastLogonTimestamp", "whenCreated"])
        except ldb.LdbError as e:
            if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:      # an OU not converged yet holds nothing
                raise
    for m in found:
        one = lambda name: str(m.get(name, idx=0) or "")    # noqa: E731
        created = one("whenCreated")
        out.append({"name": one("sAMAccountName").rstrip("$").lower(), "dns": one("dNSHostName"),
                    "os": one("operatingSystem"), "enabled": not int(one("userAccountControl") or 0) & ACCOUNTDISABLE,
                    "last_logon": _when(one("lastLogonTimestamp")),
                    "created": f"{created[0:4]}-{created[4:6]}-{created[6:8]}" if len(created) >= 8 else "",
                    "dn": str(m.dn)})
    return sorted(out, key=lambda x: x["name"])
