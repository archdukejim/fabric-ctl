def tier_policy_defaults(policy, have=None):
    """Purpose: the tiers' password policies as a new install starts them (2.1.6.69, 2.1.6.71; manual 1.6.12.10): each
             a copy of the domain's default policy, the Enterprise Admin's with 3 failed sign-ins, then 15 minutes'
             lockout that ends by itself (window 15 minutes). A tier already set is kept as it is.
    Inputs:  policy — the domain's password policy (ad_password_policy, every key); have — the tiers' policies already
             set (ad_tier_password_policies) or None.
    Returns: dict {"enterprise_admin": policy, "directory_admins": policy}.
    Fails:   never.
    Feeds:   setup/collect_vars."""
    have = have if isinstance(have, dict) else {}
    out = {"enterprise_admin": {**policy, "lockout_threshold": 3, "lockout_minutes": 15, "lockout_window_minutes": 15},
           "directory_admins": dict(policy)}
    return {tier: have[tier] if isinstance(have.get(tier), dict) else wanted for tier, wanted in out.items()}
