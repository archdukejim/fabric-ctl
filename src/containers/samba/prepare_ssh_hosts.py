import ldb

from list_ssh_hosts import AUX, list_ssh_hosts


def prepare_ssh_hosts(samdb, lp, site):
    """Purpose: let each managed, enabled machine of the site publish its SSH host keys (manual 1.6.11.9.7): its
             computer account gets the auxiliary class fabricSshHost, without which AD refuses fabricSshHostKey.
             The machine's right to write that one attribute on its own account comes from the site's access
             entries (ensure_site_acl: SELF, inherited on OU=machines); a machine cannot add the class itself. Machines
             outside <site>-fabric-machines are left as they are. A second call changes nothing.
    Inputs:  samdb — SamDB (as the site's agent: full control below the site's OU); lp — LoadParm (unused); site — str.
    Returns: {"prepared": [names given the class now]}.
    Fails:   ldb.LdbError from the search or a change (ERR_INSUFFICIENT_ACCESS_RIGHTS; ERR_OBJECT_CLASS_VIOLATION when
             the schema has no fabricSshHost yet: the DC has not converged since 0.9).
    Feeds:   directory_ops (op "prepare_ssh_hosts") <- vault/ssh/sign_ssh_hosts."""
    done = []
    for m in list_ssh_hosts(samdb, lp, site):
        if m["managed"] and m["enabled"] and not m["prepared"]:
            samdb.modify(ldb.Message.from_dict(samdb, {"dn": m["dn"], "objectClass": AUX}, ldb.FLAG_MOD_ADD))
            done.append(m["name"])
    return {"prepared": done}
