import ldb

import paths

NEVER = -0x8000000000000000          # AD's "never" for an age or a lockout duration
TICKS_PER_MINUTE = 60 * 10 ** 7      # AD counts durations in 100-nanosecond ticks, negative
# tier -> (the fine-grained password policy's name, its precedence: the lower wins, 2.1.6.71)
PSOS = {"enterprise_admin": ("fabric-enterprise-admin", 1), "directory_admins": ("fabric-directory-admins", 2)}
ENTERPRISE_ADMIN, DIRECTORY_ADMINS = "fabric-admin", "directory-admins"
ATTRS = ["msDS-PasswordSettingsPrecedence", "msDS-PasswordReversibleEncryptionEnabled", "msDS-PasswordHistoryLength",
         "msDS-PasswordComplexityEnabled", "msDS-MinimumPasswordLength", "msDS-MinimumPasswordAge",
         "msDS-MaximumPasswordAge", "msDS-LockoutThreshold", "msDS-LockoutObservationWindow", "msDS-LockoutDuration",
         "msDS-PSOAppliesTo"]


def _ticks(minutes):
    """Purpose: a duration as AD stores it.
    Inputs:  minutes — int; 0 means never.
    Returns: str, negative ticks, or AD's "never".
    Fails:   never.
    Feeds:   _wanted."""
    return str(NEVER if minutes == 0 else -minutes * TICKS_PER_MINUTE)


def _wanted(policy, precedence):
    """Purpose: a fine-grained password policy's attributes from one of fabric's policies.
    Inputs:  policy — dict with every key of ad_password_policy; precedence — int.
    Returns: dict {attribute: str}.
    Fails:   KeyError for a missing key (fabric checks the policies first: check_tier_policies).
    Feeds:   ensure_tier_policies."""
    return {"msDS-PasswordSettingsPrecedence": str(precedence), "msDS-PasswordReversibleEncryptionEnabled": "FALSE",
            "msDS-PasswordHistoryLength": str(policy["history"]),
            "msDS-PasswordComplexityEnabled": "TRUE" if policy["complexity"] else "FALSE",
            "msDS-MinimumPasswordLength": str(policy["minimum_length"]),
            "msDS-MinimumPasswordAge": str(-policy["minimum_age_days"] * 24 * 60 * TICKS_PER_MINUTE),
            "msDS-MaximumPasswordAge": _ticks(policy["maximum_age_days"] * 24 * 60),
            "msDS-LockoutThreshold": str(policy["lockout_threshold"]),
            "msDS-LockoutObservationWindow": str(-policy["lockout_window_minutes"] * TICKS_PER_MINUTE),
            "msDS-LockoutDuration": _ticks(policy["lockout_minutes"])}


def _target(samdb, tier):
    """Purpose: what a tier's policy applies to: fabric-admin's own account (in OU=people), or the
             directory-admins group (in OU=groups).
    Inputs:  samdb — SamDB; tier — a key of PSOS.
    Returns: str DN, or None while it does not exist (fabric-admin before setup's admin step).
    Fails:   ldb.LdbError from the search.
    Feeds:   ensure_tier_policies."""
    folder, name = ("people", ENTERPRISE_ADMIN) if tier == "enterprise_admin" else ("groups", DIRECTORY_ADMINS)
    found = samdb.search(base=paths.folder_dn(samdb, folder), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                         expression=f"(sAMAccountName={name})")
    return str(found[0].dn) if found else None


def ensure_tier_policies(samdb, policies):
    """Purpose: the tiers' own password policies (2.1.6.69, 2.1.6.71) as AD fine-grained password policies in the
             Password Settings Container, beside the domain's default: `fabric-enterprise-admin` (precedence 1) on
             fabric-admin's own account, `fabric-directory-admins` (precedence 2) on the directory-admins group. Made
             when missing, then only what differs is written; a policy whose target does not exist yet applies to
             nothing until it does.
    Inputs:  samdb — SamDB (as the system); policies — {"enterprise_admin": policy, "directory_admins": policy}, each
             with every key of ad_password_policy (checked by fabric first: check_tier_policies).
    Returns: list of str, what changed.
    Fails:   KeyError for a missing tier or key; ldb.LdbError if AD refuses a value.
    Feeds:   converge (at the root, every convergence), ensure_enterprise_admin (at once, when fabric-admin is made)."""
    container = f"CN=Password Settings Container,CN=System,{samdb.domain_dn()}"
    done = []
    for tier, (name, precedence) in PSOS.items():
        dn = f"CN={name},{container}"
        wanted = _wanted(policies[tier], precedence)
        target = _target(samdb, tier)
        try:
            have = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=ATTRS)[0]
        except ldb.LdbError as e:
            if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
                raise
            samdb.add({"dn": dn, "objectClass": "msDS-PasswordSettings", **wanted,
                       **({"msDS-PSOAppliesTo": target} if target else {})})
            done.append(f"password policy {name} created" + (f", on {target}" if target else ""))
            continue
        changed = {k: x for k, x in wanted.items() if str(have.get(k, [""])[0]) != x}
        if changed:
            samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, **changed}, ldb.FLAG_MOD_REPLACE))
            done += [f"password policy {name}: {k}" for k in sorted(changed)]
        applies = sorted(str(x).lower() for x in have.get("msDS-PSOAppliesTo", []))
        if target and applies != [target.lower()]:
            samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "msDS-PSOAppliesTo": target}, ldb.FLAG_MOD_REPLACE))
            done.append(f"password policy {name}: on {target}")
    return done
