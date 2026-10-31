import re

import ldap.filter

from directory import folder_dn, load_config, search
from mappings import account_groups, best_mapping

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}\$?$")
ACCOUNTDISABLE = 0x2


def check_peap(name):
    """Purpose: decide an account whose PEAP-MSCHAPv2 answer the domain has just accepted (through ntlm_auth): may it
             join, and on which VLAN (manual 1.6.3.10). A person (`alice`): one in OU=people, never a service
             account. A domain machine (`ws1$`, from `host/ws1.<domain>`): only one in OU=machines (and below;
             2.1.11.3), never a fabric host or a DC. Either must be in a group mapped in fabric-radius.json "people".
    Inputs:  name — str, the account's sAMAccountName as mschap gives it (a machine's ends in "$").
    Returns: dict {account, machine (bool), allowed, vlan, reason}; when allowed also "group" (the best mapping).
    Fails:   ldap errors (directory down, timeout) and config errors (OSError, KeyError) propagate; the caller turns
             them into Access-Reject.
    Feeds:   fabric_radius._decide_peap."""
    conf = load_config()
    machine = (name or "").endswith("$")
    out = {"account": name or "-", "machine": machine, "allowed": False, "vlan": None}
    if not NAME_RE.match(name or ""):
        return dict(out, reason="not an account name")
    attrs = ["memberOf", "primaryGroupID", "userAccountControl"]
    value = ldap.filter.escape_filter_chars(name)
    if machine:
        found = search(folder_dn(conf, "machines"), "(&(objectCategory=computer)(sAMAccountName=%s))" % value,
                       attrs, subtree=True)
    else:
        found = search(folder_dn(conf, "people"),
                       "(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))" % value, attrs, subtree=True)
    if len(found) != 1:
        return dict(out, reason="not a machine in OU=machines" if machine else "no such person")
    _, a = found[0]
    if int((a.get("userAccountControl") or [b"0"])[0]) & ACCOUNTDISABLE:
        return dict(out, reason="account disabled")
    best = best_mapping(conf.get("people"), account_groups(a, folder_dn(conf, "groups")))
    if not best:
        return dict(out, reason="in no group mapped for 802.1X")
    return dict(out, allowed=True, vlan=best[1], reason="", group=best[0])
