"""Which `radius_people` mapping an account falls under (manual 1.6.3.10, 2.1.11.3): the same rule for people (EAP-TTLS,
PEAP) and domain machines (PEAP)."""

# primary groups, which memberOf never lists: Domain Users (fabric's `users`, 2.1.9.11) and Domain Computers
PRIMARY_GROUPS = {"513": {"domain users", "users"}, "515": {"domain computers"}}


def account_groups(attrs, groups_dn):
    """Purpose: the names of an account's groups, as radius_people names them (lower case).
    Inputs:  attrs — dict {attr: [bytes]} with memberOf and primaryGroupID; groups_dn — str, the DN of the domain's
             OU=groups (1.6.13.2).
    Returns: set of str: the CN of each group in OU=groups (and below; AD's own groups such as Guests or
             Administrators never match a mapping), and the primary group's names (PRIMARY_GROUPS).
    Fails:   UnicodeDecodeError for a value that is not UTF-8.
    Feeds:   check_person, check_peap."""
    tail = "," + groups_dn.lower()
    groups = {dn.split(",", 1)[0][3:].lower() for dn in (v.decode() for v in attrs.get("memberOf") or [])
              if dn.lower().endswith(tail)}
    for rid in (v.decode() for v in attrs.get("primaryGroupID") or []):
        groups |= PRIMARY_GROUPS.get(rid, set())
    return groups


def best_mapping(mappings, groups):
    """Purpose: the mapping an account joins under, and its VLAN.
    Inputs:  mappings — fabric-radius.json "people" [{group, vlan, priority}]; groups — account_groups' set.
    Returns: (group name, VLAN or None) — the group of the mapping with the lowest priority number (ties by group
             name), the VLAN of the first such mapping that sets one; None when no mapping matches.
    Fails:   KeyError for a mapping without "group".
    Feeds:   check_person, check_peap."""
    mapped = sorted((m for m in mappings or [] if m["group"].lower() in groups),
                    key=lambda m: (m.get("priority", 100), m["group"]))
    if not mapped:
        return None
    return mapped[0]["group"], next((m["vlan"] for m in mapped if m.get("vlan")), None)
