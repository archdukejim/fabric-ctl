import ldb

from ad_time import ad_time
from find_machine import MACHINE_FOLDERS
import paths

ACCOUNTDISABLE = 0x2
TYPES = {f"machines-{ou}": kind for kind, ou in paths.MACHINE_TYPES.items()}      # a type group -> its type


def list_machines(samdb, lp, site):
    """Purpose: the domain's machines (manual 1.6.7.6, 1.6.5.21 S7.4, 1.6.13.3): the computer accounts in OU=machines
             and the OUs below it, Windows and Linux alike, and the fabric hosts in OU=fabric-hosts (1.6.11.11), each
             with its type and sites (from its groups).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: machines are the
             domain's; a machine's sites are its `site-<name>` groups).
    Returns: list of {"name" (the host name, lower case), "dns", "os", "type" (server, desktop, network, or ""),
             "sites" (site names), "enabled", "last_logon" (ISO or ""), "created" (ISO), "dn"}, sorted by name.
    Fails:   ldb.LdbError from the search.
    Feeds:   directory_ops (op "list_machines")."""
    out, found = [], []
    for folder in MACHINE_FOLDERS:
        try:
            found += samdb.search(base=paths.folder_dn(samdb, folder), scope=ldb.SCOPE_SUBTREE,
                                  expression="(objectCategory=computer)",
                                  attrs=["sAMAccountName", "dNSHostName", "operatingSystem", "userAccountControl",
                                         "lastLogonTimestamp", "whenCreated", "memberOf"])
        except ldb.LdbError as e:
            if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:      # a folder not converged yet holds nothing
                raise
    for m in found:
        one = lambda name: str(m.get(name, idx=0) or "")    # noqa: E731
        created = one("whenCreated")
        groups = [str(g).split(",", 1)[0].split("=", 1)[1] for g in m.get("memberOf", [])]
        out.append({"name": one("sAMAccountName").rstrip("$").lower(), "dns": one("dNSHostName"),
                    "os": one("operatingSystem"), "type": next((TYPES[g] for g in groups if g in TYPES), ""),
                    "sites": sorted(g[len("site-"):] for g in groups if g.startswith("site-")),
                    "enabled": not int(one("userAccountControl") or 0) & ACCOUNTDISABLE,
                    "last_logon": ad_time(one("lastLogonTimestamp")),
                    "created": f"{created[0:4]}-{created[4:6]}-{created[6:8]}" if len(created) >= 8 else "",
                    "dn": str(m.dn)})
    return sorted(out, key=lambda x: x["name"])
