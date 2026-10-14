import ldb

import paths
from site_roles import CLASSES

IN_CHAIN = "1.2.840.113556.1.4.1941"        # LDAP_MATCHING_RULE_IN_CHAIN: membership through nested groups too
SUFFIX = "-remote-users"


def ssh_user_sites(samdb, lp, site, uid):
    """Purpose: the sites and machine classes a person may sign in to remotely (decision 2.1.7.14 as revised
             2026-10-13, manual 1.6.11.9.14): a member, directly or through nested groups, of
             `<s>-<class>-remote-users`, counted only where that group sits in site s's own `OU=groups` (a group of
             that name anywhere else counts for nothing) — the principals `<uid>@<s>-<class>` of the person's SSH
             certificate.
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str (the asking site, unused: which
             of these it signs for is the host's to judge); uid — the user name.
    Returns: {"uid", "grants": [{"site", "class"}], sorted by site then class}.
    Fails:   ValueError("no such user: …") for a name that is not a person (kind "invalid"); ldb.LdbError from a search.
    Feeds:   directory_ops (op "ssh_user_sites") <- fabriclib/directory/ssh_user_sites."""
    base = samdb.domain_dn()
    person = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                          expression=f"(&(objectCategory=person)(objectClass=user)"
                                     f"(sAMAccountName={ldb.binary_encode(uid)}))")
    if len(person) != 1:
        raise ValueError(f"no such user: {uid}")
    groups = samdb.search(base=paths.sites_dn(samdb), scope=ldb.SCOPE_SUBTREE, attrs=["sAMAccountName"],
                          expression=f"(&(objectClass=group)(sAMAccountName=*{SUFFIX})"
                                     f"(member:{IN_CHAIN}:={ldb.binary_encode(str(person[0].dn))}))")
    grants = []
    for g in groups:
        name = str(g["sAMAccountName"][0])
        owner, _, cls = name[:-len(SUFFIX)].rpartition("-")
        if cls not in CLASSES or not owner:
            continue
        try:
            home = paths.site_dn(samdb, owner)
        except LookupError:
            continue
        grant = {"site": owner, "class": cls}
        if str(g.dn).lower() == f"cn={name},ou=groups,{home}".lower() and grant not in grants:
            grants.append(grant)
    return {"uid": uid, "grants": sorted(grants, key=lambda x: (x["site"], x["class"]))}
