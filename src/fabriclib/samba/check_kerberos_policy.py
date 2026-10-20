from fabriclib.common.errors import ValidationError

# AD's own defaults (Windows' Default Domain Policy): 10-hour tickets, renewable for 7 days, 5 minutes' clock skew
DEFAULT = {"ticket_hours": 10, "renew_days": 7, "skew_minutes": 5}


def check_kerberos_policy(policy):
    """Purpose: refuse a Kerberos ticket policy outside its working range (manual 1.6.12.9): a ticket at least 1 hour
             and never longer than its renewal, a renewal at most 30 days, a clock skew of 1 to 15 minutes (Windows'
             and MIT's working range; a wider skew weakens replay protection).
    Inputs:  policy — dict with ticket_hours, renew_days, skew_minutes (whole numbers), and no other key.
    Returns: None.
    Fails:   ValidationError naming the first problem.
    Feeds:   deploy/check_samba_settings, samba/set_kerberos_policy."""
    if not isinstance(policy, dict) or set(policy) != set(DEFAULT):
        raise ValidationError(f"ad_kerberos_policy: exactly {', '.join(DEFAULT)}")
    for key, value in policy.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError(f"ad_kerberos_policy: {key} must be a whole number")
    hours, days, skew = policy["ticket_hours"], policy["renew_days"], policy["skew_minutes"]
    if not 1 <= days <= 30:
        raise ValidationError(f"the maximum renewal age is 1 to 30 days, not {days}")
    if hours < 1:
        raise ValidationError(f"the maximum ticket age is at least 1 hour, not {hours}")
    if hours > days * 24:
        raise ValidationError(f"the maximum ticket age ({hours} hours) is over the renewal age ({days} days)")
    if not 1 <= skew <= 15:
        raise ValidationError(f"the clock skew allowed is 1 to 15 minutes (Windows' and MIT's working range; a wider "
                              f"skew weakens replay protection), not {skew}")
