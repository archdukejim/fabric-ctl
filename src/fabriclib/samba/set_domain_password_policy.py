from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.deploy.check_samba_settings import check_samba_settings


def set_domain_password_policy(actor, changes, source="cli"):
    """Purpose: change the domain's password policy (2.1.6.13: the admin's; manual 1.6.3.8). The whole policy is checked
             again; the next apply writes it into the domain.
    Inputs:  actor — str, who asks (audit); changes — dict of policy keys to new values (minimum_length, complexity,
             history, minimum_age_days, maximum_age_days, lockout_threshold, lockout_minutes, lockout_window_minutes);
             source — "cli" (default) or "web". Reads and writes vars.yaml under vars_lock.
    Returns: dict, the saved policy.
    Fails:   ValidationError from check_samba_settings (a key unknown, out of range,
             or the policy inconsistent); OSError or yaml.YAMLError from the vars file or the audit log.
    Feeds:   run_domain_command (password-policy); agent/post_domain (POST /v1/domain/password-policy, the
             console's Domain section, domain:admin)."""
    with vars_lock():
        data = load_vars()
        policy = {**(data.get("ad_password_policy") or {}), **changes}
        # the settings file holds what the admin set: the rendered defaults fill the rest (vars.yaml.j2)
        ad = str(data.get("ad_domain") or "").lower()
        check_samba_settings({"ad_rpc_ports": "49152-49251", "ad_old_password_minutes": 0, **data, "ad_domain": ad,
                              "ad_netbios": str(data.get("ad_netbios") or ad.split(".")[0])[:15].upper(),
                              "ad_password_policy": policy})
        data["ad_password_policy"] = policy
        save_vars(data)
    write_audit(actor, "AD_PASSWORD_POLICY", " ".join(f"{k}={v}" for k, v in sorted(changes.items())), source)
    return policy
