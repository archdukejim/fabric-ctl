import ldb

from legacy_logon_groups import legacy_logon_groups


def logon_groups(samdb, lp, site, names=(), admin_group="admins"):
    """Purpose: what the log-on policy editor needs from the domain (manual 1.6.11.4): which of the groups it is given
             do not exist, and the groups the site grants log-on to while it has no per-OU policy (the first edit
             makes them the site OU's policy, so nothing changes but what was edited).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; names — list of group names
             (sAMAccountName) to look for; admin_group — the web console's admin group.
    Returns: {"missing": [names with no group of that name, as given], "legacy": legacy_logon_groups' list}.
    Fails:   LookupError (no such site); ldb.LdbError from a search.
    Feeds:   directory_ops (op "logon_groups")."""
    base = str(samdb.domain_dn())
    missing = [n for n in names
               if not samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                                   expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(n)}))")]
    return {"missing": missing, "legacy": legacy_logon_groups(samdb, site, admin_group)}
