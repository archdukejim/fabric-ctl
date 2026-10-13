import ldb

from find_machine import MACHINE_OUS
from paths import site_dn
from site_roles import fabric_machines

ACCOUNTDISABLE = 0x2
AUX = "fabricSshHost"                # the auxiliary class holding a machine's host keys and certificates (1.6.3.5)


def list_ssh_hosts(samdb, lp, site):
    """Purpose: the site's computer accounts as SSH host certificates see them (manual 1.6.11.9.8): in its OU=machines
             (and below) and OU=fabric-hosts, whether each is managed (a member of <site>-fabric-machines) and
             enabled, whether it can publish its host keys yet (the auxiliary class fabricSshHost), the host keys it
             published (fabricSshHostKey) and the certificates fabric wrote back (fabricSshHostCert).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str.
    Returns: list of {"name" (lower case, without $), "account" (the sAMAccountName), "dn", "ou" ("machines" or
             "fabric-hosts"), "managed", "enabled", "prepared" (bool each), "dns", "keys", "certs" (lists of str)},
             sorted by name.
    Fails:   ldb.LdbError from the search (an OU not converged yet holds nothing).
    Feeds:   directory_ops (op "list_ssh_hosts") <- vault/ssh/sign_ssh_hosts, vault/ssh/ssh_hosts_overview."""
    group = f"cn={fabric_machines(site).lower()},"
    out = []
    for ou in MACHINE_OUS:
        try:
            found = samdb.search(base=f"OU={ou},{site_dn(samdb, site)}", scope=ldb.SCOPE_SUBTREE,
                                 expression="(objectCategory=computer)",
                                 attrs=["sAMAccountName", "dNSHostName", "userAccountControl", "memberOf",
                                        "objectClass", "fabricSshHostKey", "fabricSshHostCert"])
        except ldb.LdbError as e:
            if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
                raise
            continue
        for m in found:
            account = str(m.get("sAMAccountName", idx=0) or "")
            out.append({"name": account.rstrip("$").lower(), "account": account, "dn": str(m.dn), "ou": ou,
                        "managed": any(str(g).lower().startswith(group) for g in m.get("memberOf", [])),
                        "enabled": not int(str(m.get("userAccountControl", idx=0) or 0)) & ACCOUNTDISABLE,
                        "prepared": AUX in [str(c) for c in m.get("objectClass", [])],
                        "dns": str(m.get("dNSHostName", idx=0) or ""),
                        "keys": sorted(str(k) for k in m.get("fabricSshHostKey", [])),
                        "certs": sorted(str(c) for c in m.get("fabricSshHostCert", []))})
    return sorted(out, key=lambda x: x["name"])
