from fabriclib.access.check_access import check_access
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.samba.check_kerberos_policy import DEFAULT, check_kerberos_policy


def set_kerberos_policy(actor, changes, caller=None, source="cli", container="samba"):
    """Purpose: change the domain's Kerberos ticket policy (manual 1.6.12.9; `domain:admin`, the Directory
             Administrators): the maximum ticket age (hours), renewal age (days) and clock skew (minutes), domain-wide.
             The whole policy is checked again; the next apply writes it to the DC (its KDC's lifetimes in smb.conf and
             its clock skew in its krb5.conf), restarting it health-gated.
    Inputs:  actor — str, for the audit; changes — dict of ticket_hours, renew_days, skew_minutes to change; caller —
             the signed-in person's user name (fabric-agent's check: a Directory Administrator), or None (root);
             source — audit source; container — the DC's container (the check). Reads and writes vars.yaml under
             vars_lock.
    Returns: dict, the saved policy.
    Fails:   ValidationError from check_access, or check_kerberos_policy (an unknown key, a ticket under 1 hour or
             over the renewal, a renewal over 30 days, a skew under 1 or over 15 minutes); OSError, yaml.YAMLError.
    Feeds:   domain/run_kerberos_command (`fabricctl domain kerberos policy`); agent route POST
             /v1/domain/kerberos/policy.
    Notes:   audited AD_KERBEROS_POLICY."""
    check_access(load_vars(), caller, "domain:admin", {}, container)
    with vars_lock():
        data = load_vars()
        policy = {**DEFAULT, **(data.get("ad_kerberos_policy") or {}), **changes}
        check_kerberos_policy(policy)
        data["ad_kerberos_policy"] = policy
        save_vars(data)
    write_audit(actor, "AD_KERBEROS_POLICY", " ".join(f"{k}={v}" for k, v in sorted(changes.items())), source)
    return policy
