from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.samba.check_tier_policies import TIERS, check_tier_policies


def set_tier_password_policy(actor, tier, changes):
    """Purpose: change one tier's own password policy (2.1.6.71): fabric-admin's (`enterprise_admin`) or the
             Directory Administrators' (`directory_admins`), both set only on the host by root, acting for the
             Enterprise Admin (`fabricctl domain password-policy --tier`); never from the console or the agent. Both
             policies are checked again; the next apply writes them into the domain as fine-grained password policies.
    Inputs:  actor — str, who asks (audit); tier — "enterprise_admin" or "directory_admins"; changes — dict of policy
             keys to new values. Reads and writes vars.yaml under vars_lock.
    Returns: dict, the tier's saved policy.
    Fails:   ValidationError for an unknown tier, before the install has the tiers' policies (setup adds them), or
             from check_tier_policies; OSError or yaml.YAMLError from the vars file or the audit log.
    Feeds:   samba/run_domain_command (password-policy --tier)."""
    if tier not in TIERS:
        raise ValidationError(f"unknown tier {tier!r}: enterprise-admin or directory-admins")
    with vars_lock():
        data = load_vars()
        policies = data.get("ad_tier_password_policies")
        if not isinstance(policies, dict) or tier not in policies:
            raise ValidationError("this install has no tiers' password policies yet: setup adds them (2.1.6.71)")
        policies = {**policies, tier: {**policies[tier], **changes}}
        check_tier_policies(policies)
        data["ad_tier_password_policies"] = policies
        save_vars(data)
    write_audit(actor, "AD_TIER_PASSWORD_POLICY",
                f"tier={tier} " + " ".join(f"{k}={v}" for k, v in sorted(changes.items())), "cli")
    return policies[tier]
