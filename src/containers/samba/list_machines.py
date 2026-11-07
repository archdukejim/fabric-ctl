from ad_time import ad_time
from all_machines import all_machines
from host_groups import PREFIX
from ou_paths import ou_path
import paths

ACCOUNTDISABLE = 0x2
TYPES = {f"machines-{ou}": kind for kind, ou in paths.MACHINE_TYPES.items()}      # a type group -> its type


def list_machines(samdb, lp, site):
    """Purpose: the domain's machines (manual 1.6.7.6, 1.6.5.21 S7.4, 1.6.13.3): the computer accounts in any OU
             (OU=machines and below, an admin's own OUs anywhere since 0.9.2, 1.8.8.5), Windows and Linux alike, and the
             fabric hosts in OU=fabric-hosts (1.6.11.11), each with its type, sites and machine groups (from its
             groups: its type is its group's, never its OU's, 2.1.6.99) and its folder.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: machines are the
             domain's; a machine's sites are its `site-<name>` groups).
    Returns: list of {"name" (the host name, lower case), "dns", "os", "type" (server, desktop, network, or ""),
             "sites" (site names), "groups" (its machine groups, `hosts-<name>`), "folder" (the OU it is in, by
             path: "machines/servers"), "enabled", "last_logon" (ISO or ""), "created" (ISO), "dn"}, sorted by
             name.
    Fails:   ldb.LdbError from the search.
    Feeds:   directory_ops (op "list_machines")."""
    out = []
    found = all_machines(samdb, "", ["sAMAccountName", "dNSHostName", "operatingSystem", "lastLogonTimestamp",
                                     "whenCreated", "memberOf"])
    for m in found:
        one = lambda name: str(m.get(name, idx=0) or "")    # noqa: E731
        created = one("whenCreated")
        groups = [str(g).split(",", 1)[0].split("=", 1)[1] for g in m.get("memberOf", [])]
        out.append({"name": one("sAMAccountName").rstrip("$").lower(), "dns": one("dNSHostName"),
                    "os": one("operatingSystem"), "type": next((TYPES[g] for g in groups if g in TYPES), ""),
                    "sites": sorted(g[len("site-"):] for g in groups if g.startswith("site-")),
                    "groups": sorted(g for g in groups if g.startswith(PREFIX)),
                    "folder": ou_path(samdb, str(m.dn).split(",", 1)[1]),
                    "enabled": not int(one("userAccountControl") or 0) & ACCOUNTDISABLE,
                    "last_logon": ad_time(one("lastLogonTimestamp")),
                    "created": f"{created[0:4]}-{created[4:6]}-{created[6:8]}" if len(created) >= 8 else "",
                    "dn": str(m.dn)})
    return sorted(out, key=lambda x: x["name"])
