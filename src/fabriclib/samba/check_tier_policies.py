from fabriclib.common.errors import ValidationError
from fabriclib.samba.check_password_policy import check_password_policy

# the tiers' own password policies (2.1.6.71): key -> who it is for; the CLI's --tier names them with hyphens
TIERS = {"enterprise_admin": "fabric-admin, the Enterprise Admin", "directory_admins": "the Directory Administrators"}


def check_tier_policies(policies):
    """Purpose: the tiers' password policies (2.1.6.71) checked as AD will take them: both tiers there, each a whole
             policy as the domain's (check_password_policy); and the Enterprise Admin's never locked until an admin
             unlocks it (a lockout of 0 minutes), since break glass that can be locked out for good is no break glass
             (2.1.6.69), and never without a lockout (a threshold of 0), which would leave it open to guessing
             (2.1.6.91).
    Inputs:  policies — dict {"enterprise_admin": policy, "directory_admins": policy}.
    Returns: None.
    Fails:   ValidationError naming the tier and the first problem.
    Feeds:   deploy/check_samba_settings (before anything is rendered), samba/set_tier_password_policy."""
    if not isinstance(policies, dict) or set(policies) != set(TIERS):
        raise ValidationError("ad_tier_password_policies needs exactly enterprise_admin and directory_admins "
                              "(2.1.6.71)")
    for tier, who in TIERS.items():
        try:
            check_password_policy(policies[tier])
        except ValidationError as e:
            raise ValidationError(f"the password policy of {who}: {e}") from None
    if policies["enterprise_admin"]["lockout_threshold"] == 0:
        raise ValidationError("the password policy of fabric-admin, the Enterprise Admin: a lockout threshold of 0 "
                              "(never locked out, so open to guessing from afar) is refused: it locks after a few "
                              "failed sign-ins, then unlocks by itself (2.1.6.69, 2.1.6.91)")
    if policies["enterprise_admin"]["lockout_minutes"] == 0:
        raise ValidationError("the password policy of fabric-admin, the Enterprise Admin: a lockout of 0 minutes "
                              "(until an admin unlocks it) is refused: break glass must unlock by itself (2.1.6.69)")
