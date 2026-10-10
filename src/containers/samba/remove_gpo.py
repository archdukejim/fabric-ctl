import os
import shutil

import ldb

from find_gpo import find_gpo


def remove_gpo(samdb, lp, name):
    """Purpose: one of fabric's GPOs gone (manual 1.6.11.4): unlinked from every object that links it (the domain, any
             OU, any AD site), its container deleted with its Machine and User children, its SYSVOL folder removed —
             what `samba-tool gpo del` does, locally on the DC's own database (no SMB, no credentials).
    Inputs:  samdb — SamDB (as the system); lp — LoadParm (realm, the SYSVOL path); name — the GPO's display name.
    Returns: list of str, what was unlinked and removed ([] when there is no such GPO).
    Fails:   ldb.LdbError from AD; OSError removing the folder is ignored (a site's DC may never have had it).
    Feeds:   ensure_logon_policies (a log-on policy no longer wanted, the site's legacy one included)."""
    found = find_gpo(samdb, name)
    if found is None:
        return []
    dn, guid, _ = found
    done = []
    for obj in samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, expression="(gPLink=*)",
                            attrs=["gPLink"]):
        current = str(obj["gPLink"][0])
        parts = [p for p in current.strip("[]").split("][") if p]
        kept = [p for p in parts if guid.lower() not in p.lower()]
        if len(kept) == len(parts):
            continue
        msg = ldb.Message(obj.dn)        # an empty value list removes the attribute: AD keeps no empty values
        msg["gPLink"] = ldb.MessageElement(["".join(f"[{p}]" for p in kept)] if kept else [], ldb.FLAG_MOD_REPLACE,
                                           "gPLink")
        samdb.modify(msg)
        done.append(f"GPO {name} unlinked from {obj.dn}")
    samdb.delete(dn, ["tree_delete:1"])
    shutil.rmtree(os.path.join(lp.get("path", "sysvol"), lp.get("realm").lower(), "Policies", guid),
                  ignore_errors=True)
    done.append(f"GPO {name} removed")
    return done
