"""Who and what a grant's groups hold (manual 1.6.13.4): a group's people and computers, nesting followed and a
primary group's members included; and those no grant ever reaches (the top tier, fabric's own accounts, the hosts
that run a DC, 1.6.13.6) or manages (the Directory Administrators, 2.1.6.66)."""
import re

import ldb

from group_names import DC_HOSTS, DIRECTORY_ADMINS

IN_CHAIN = "1.2.840.113556.1.4.1941"          # LDAP_MATCHING_RULE_IN_CHAIN: nested membership followed
TOP_RIDS = (519, 518, 512)                    # Enterprise, Schema and Domain Admins (2.1.6.68)
DC_RIDS = (516, 521)                          # a DC's primary group: Domain Controllers, Read-only DCs
FABRIC_ACCOUNTS = ("fabric-agent-", "fabric-keycloak-", "fabric-radius-", "fabric-sso-", "fabric-join-")
NOT_PEOPLE = {"krbtgt", "guest"}
SAMBA_DNS = re.compile(r"^dns-dc-[0-9]{4}$")         # Samba's own DNS account per DC (CN=Users)


def find_group(samdb, name):
    """Purpose: a group anywhere in the domain by its name (AD's own Builtin ones included).
    Inputs:  samdb — SamDB; name — sAMAccountName.
    Returns: (dn str, sid str), or None when there is no such group.
    Fails:   ldb.LdbError from the search.
    Feeds:   group_members, check_grant, compile_grants."""
    res = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=["objectSid"],
                       expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))")
    if not res:
        return None
    return str(res[0].dn), str(samdb.schema_format_value("objectSid", res[0]["objectSid"][0]), "utf-8")


def group_members(samdb, name):
    """Purpose: the people and computers in a group, nesting followed, its primary-group members too (Domain Users
             holds everyone that way, not by `member`).
    Inputs:  samdb — SamDB; name — the group's sAMAccountName.
    Returns: {"people": {dn: sAMAccountName}, "computers": {dn: sAMAccountName}}; both empty for no such group.
    Fails:   ldb.LdbError from a search.
    Feeds:   compile_grants, explain_grants, excluded."""
    out = {"people": {}, "computers": {}}
    found = find_group(samdb, name)
    if found is None:
        return out
    dn, sid = found
    expr = f"(memberOf:{IN_CHAIN}:={ldb.binary_encode(dn)})"
    domain_sid = str(samdb.get_domain_sid())
    if sid.startswith(domain_sid + "-"):
        expr = f"(|{expr}(primaryGroupID={sid.rsplit('-', 1)[1]}))"
    for m in samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, expression=expr,
                          attrs=["objectClass", "sAMAccountName"]):
        classes = {str(c).lower() for c in m.get("objectClass", [])}
        account = str(m["sAMAccountName"][0]) if m.get("sAMAccountName") else ""
        if "computer" in classes:
            out["computers"][str(m.dn).lower()] = account
        elif "user" in classes:
            out["people"][str(m.dn).lower()] = account
    return out


def excluded(samdb):
    """Purpose: those no grant reaches, and those no grant's people rights manage: AD's top tier (members of
             Enterprise, Schema or Domain Admins or Administrators, nesting followed, or carrying adminCount), fabric's
             own service accounts, AD's krbtgt and Guest, Samba's DNS accounts; the Directory Administrators (managed
             only by the tier above, 2.1.6.66); the hosts that run a DC and the DCs themselves (1.6.13.6).
    Inputs:  samdb — SamDB.
    Returns: {"top": set of dn (lower case), "directory_admins": set, "dc_hosts": set}.
    Fails:   ldb.LdbError from a search.
    Feeds:   compile_grants, explain_grants, authorize_action."""
    t = tiers(samdb)
    return {"top": t["ad_top"] | t["fabric_accounts"], "directory_admins": t["directory_admins"],
            "dc_hosts": t["dc_hosts"]}


def tiers(samdb):
    """Purpose: the accounts of each tier (2.1.6.68) and fabric's own, apart: AD's top tier (members of Enterprise,
             Schema or Domain Admins or Administrators, nesting followed, or carrying adminCount: the Enterprise
             Admin's tier); fabric's own service accounts, AD's krbtgt and Guest and Samba's DNS accounts (nobody's to
             manage); the Directory Administrators; the hosts that run a DC and the DCs themselves (1.6.13.6).
    Inputs:  samdb — SamDB.
    Returns: {"ad_top": set of dn (lower case), "fabric_accounts": set, "directory_admins": set, "dc_hosts": set}.
    Fails:   ldb.LdbError from a search.
    Feeds:   excluded, authorize_action."""
    base, sid = str(samdb.domain_dn()), str(samdb.get_domain_sid())
    top, own = set(), set()
    for rid in TOP_RIDS:
        for m in samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, expression=f"(objectSid={sid}-{rid})",
                              attrs=["sAMAccountName"]):
            top |= set(group_members(samdb, str(m["sAMAccountName"][0]))["people"])
    top |= set(group_members(samdb, "Administrators")["people"])
    for m in samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, attrs=["sAMAccountName"],
                          expression="(&(objectClass=user)(!(objectClass=computer))(adminCount=1))"):
        top.add(str(m.dn).lower())
    for m in samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, attrs=["sAMAccountName"],
                          expression="(&(objectClass=user)(!(objectClass=computer)))"):
        name = str(m["sAMAccountName"][0]).lower() if m.get("sAMAccountName") else ""
        if name.startswith(FABRIC_ACCOUNTS) or name in NOT_PEOPLE or SAMBA_DNS.match(name):
            own.add(str(m.dn).lower())
    hosts = set(group_members(samdb, DC_HOSTS)["computers"])
    rids = "".join(f"(primaryGroupID={r})" for r in DC_RIDS)
    hosts |= {str(m.dn).lower() for m in samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                                                      expression=f"(&(objectClass=computer)(|{rids}))")}
    return {"ad_top": top - own, "fabric_accounts": own,
            "directory_admins": set(group_members(samdb, DIRECTORY_ADMINS)["people"]), "dc_hosts": hosts}


def reach(samdb, groups, out, cache=None):
    """Purpose: who a grant's who and where reach: the people in all its who groups, the people and computers in all
             its where groups, less those `excluded` leaves out (the top tier everywhere, the Directory Administrators
             from where, the DC hosts from where).
    Inputs:  samdb — SamDB; groups — {"who": [names], "where": [names]}; out — excluded's result; cache — dict, a
             group's members kept across grants (optional).
    Returns: {"who": {dn: name}, "where_people": {dn: name}, "where_computers": {dn: name}}.
    Fails:   ldb.LdbError from a search.
    Feeds:   compile_grants, explain_grants."""
    cache = {} if cache is None else cache

    def members(name):
        if name not in cache:
            cache[name] = group_members(samdb, name)
        return cache[name]

    def common(names, kind):
        sets = [members(n)[kind] for n in names]
        if not sets:
            return {}
        keep = set(sets[0]).intersection(*sets[1:])
        return {dn: sets[0][dn] for dn in sorted(keep)}

    who = {dn: n for dn, n in common(groups["who"], "people").items() if dn not in out["top"]}
    people = {dn: n for dn, n in common(groups["where"], "people").items()
              if dn not in out["top"] and dn not in out["directory_admins"]}
    computers = {dn: n for dn, n in common(groups["where"], "computers").items() if dn not in out["dc_hosts"]}
    return {"who": who, "where_people": people, "where_computers": computers}
