import re

import ldap
import ldap.filter

from directory import connect, folder_dn, load_config, search
from mappings import account_groups, best_mapping

UID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")


def check_person(uid, password):
    """Purpose: decide a person joining by password (EAP-TTLS/PAP, inside the TLS tunnel). The password is
             checked by binding to the DC as that person over verified LDAPS, so the domain's lockout policy
             counts network logins; only members of a group mapped in fabric-radius.json "people" may join
             (manual 1.6.3.10).
    Inputs:  uid — str user name (sAMAccountName, must match UID_RE); password — str. Reads fabric-radius.json and
             the people in OU=people (never the service accounts, which live in OU=service-accounts) with their
             groups.
    Returns: dict {person, allowed, vlan, reason}; when allowed also "group" (the best mapping). vlan comes from
             the mapping with the lowest priority number that sets one (ties by group name), else None.
    Fails:   ldap errors other than a refused bind (directory down, timeout) and config errors (OSError,
             KeyError) propagate; the caller turns them into Access-Reject.
    Feeds:   fabric_radius._decide_person."""
    conf = load_config()
    if not UID_RE.match(uid or "") or not password:
        return {"person": uid or "-", "allowed": False, "vlan": None, "reason": "not a user name and password"}
    users = search(
        folder_dn(conf, "people"),
        "(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))" % ldap.filter.escape_filter_chars(uid),
        ["memberOf", "primaryGroupID"], subtree=True)
    if len(users) != 1:
        return {"person": uid, "allowed": False, "vlan": None, "reason": "no such person"}
    dn, attrs = users[0]
    try:
        connect(dn, password).unbind_s()
    except (ldap.INVALID_CREDENTIALS, ldap.UNWILLING_TO_PERFORM, ldap.CONSTRAINT_VIOLATION):
        # a wrong password, or the account locked, disabled, expired or still on its one-time password
        return {"person": uid, "allowed": False, "vlan": None, "reason": "wrong password or account locked"}
    best = best_mapping(conf.get("people"), account_groups(attrs, folder_dn(conf, "groups")))
    if not best:
        return {"person": uid, "allowed": False, "vlan": None, "reason": "in no group mapped for 802.1X"}
    return {"person": uid, "allowed": True, "vlan": best[1], "reason": "", "group": best[0]}
