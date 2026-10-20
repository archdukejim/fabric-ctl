import ldb

import paths

UF_ACCOUNTDISABLE = 0x2


def _cn(dn):
    """Purpose: the first RDN's value of a DN ("CN=directory-admins,OU=groups,…" -> "directory-admins").
    Inputs:  dn — str.
    Returns: str.
    Fails:   never.
    Feeds:   list_people."""
    return dn.split(",", 1)[0].split("=", 1)[1]


def list_people(samdb, lp, site):
    """Purpose: the People page (manual 1.6.3, 1.6.13.2): every person in OU=people (service accounts live apart, in
             OU=service-accounts) and the groups of OU=groups they may be in, never a password or a hash.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: people are the domain's,
             2.1.6.64; a person's sites are their `site-<name>` groups).
    Returns: {"users": [{uid, name, mail, locked (disabled or locked out), groups [names], sites [site names, from
              their site groups], site (those names joined, for the page), uidNumber}], "groups": [{name, members
              (count)}]}, both sorted by name.
    Fails:   ldb.LdbError from a search.
    Feeds:   directory_ops (op "list_people")."""
    users = []
    for m in samdb.search(base=paths.folder_dn(samdb, "people"), scope=ldb.SCOPE_SUBTREE,
                          expression="(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))",
                          attrs=["sAMAccountName", "displayName", "mail", "memberOf", "userAccountControl",
                                 "lockoutTime", "uidNumber"]):
        uac = int(str(m.get("userAccountControl", ["0"])[0]))
        locked = bool(uac & UF_ACCOUNTDISABLE) or int(str(m.get("lockoutTime", ["0"])[0])) > 0
        groups = sorted(_cn(str(g)) for g in m.get("memberOf", []))
        sites = [g[len("site-"):] for g in groups if g.startswith("site-")]
        users.append({"uid": str(m["sAMAccountName"][0]), "name": str(m.get("displayName", [""])[0]),
                      "mail": str(m.get("mail", [""])[0]), "locked": locked, "groups": groups, "sites": sites,
                      "site": ", ".join(sites),
                      "uidNumber": int(str(m["uidNumber"][0])) if "uidNumber" in m else None})
    groups = [{"name": str(g["cn"][0]), "members": len(g.get("member", []))}
              for g in samdb.search(base=paths.folder_dn(samdb, "groups"), scope=ldb.SCOPE_SUBTREE,
                                    expression="(objectClass=group)", attrs=["cn", "member"])]
    return {"users": sorted(users, key=lambda u: u["uid"]), "groups": sorted(groups, key=lambda g: g["name"])}
