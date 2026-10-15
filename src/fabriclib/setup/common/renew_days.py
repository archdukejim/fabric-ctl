# the most days a machine password may be kept before renewal: Windows' own range for the same policy
# ("Domain member: Maximum machine account password age", 0-999)
MAX_RENEW_DAYS = 999


def renew_days(v):
    """Purpose: after how many days sssd renews the fabric host's machine password (decision 2.1.6.50, manual
             1.6.11.12): the setting host_machine_password_renew_days, 0 (never) by default.
    Inputs:  v — vars.
    Returns: int from 0 to MAX_RENEW_DAYS; 0 for a value that is not such a whole number (deploy/check_samba_settings
             refuses those at every apply, before anything uses them).
    Fails:   never.
    Feeds:   setup/common/render_member_files, consent/plan_member, setup/join_host_domain,
             deploy/check_samba_settings."""
    days = v.get("host_machine_password_renew_days", 0)
    if isinstance(days, bool) or not isinstance(days, int) or not 0 <= days <= MAX_RENEW_DAYS:
        return 0
    return days
