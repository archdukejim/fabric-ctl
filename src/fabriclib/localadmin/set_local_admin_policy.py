from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.localadmin.common.bao_call import bao_call
from fabriclib.localadmin.common.local_admin_token import local_admin_token
from fabriclib.localadmin.constants import MOUNT, POLICIES, USER
from fabriclib.localadmin.record import load_record, save_record
from fabriclib.localadmin.secret_path import secret_path


def set_local_admin_policy(v, config_dir, policy, actor, token_fn=local_admin_token, audit=write_audit):
    """Purpose: the rotation policy of the host's local-admin set (decision 2.1.7.16, manual 1.7.1.4.3): after-use (the
             default) or keep-until-checkout; kept on the host's record and with the password in OpenBao, audited
             LOCAL_ADMIN_POLICY. Root acts for the Enterprise Admin.
    Inputs:  v — rendered vars; config_dir — the install's config folder; policy — str; actor — who, for the audit;
             token_fn, audit — the parts (tests give their own).
    Returns: {"policy", "changed": bool}.
    Fails:   ValidationError, nothing changed: an unknown policy; no local-admin made by fabric here; OpenBao locked
             (the policy is kept with the password).
    Feeds:   run_local_admin_command (`fabricctl local-admin policy`)."""
    if policy not in POLICIES:
        raise ValidationError(f"the policy is one of: {', '.join(POLICIES)}")
    rec = load_record(config_dir)
    if not rec["made"]:
        raise ValidationError(f"this host has no {USER} made by fabric (`sudo fabricctl setup --step localadmin`)")
    if rec["policy"] == policy:
        return {"policy": policy, "changed": False}
    token, why = token_fn(v)
    if token is None:
        raise ValidationError(f"{why}: the policy is kept with the password in OpenBao; unlock it first")
    path = secret_path(v)
    meta = (bao_call(v, token, "GET", f"{MOUNT}/metadata/{path}").get("data") or {}).get("custom_metadata") or {}
    bao_call(v, token, "POST", f"{MOUNT}/metadata/{path}", {"custom_metadata": {**meta, "policy": policy}})
    old, rec["policy"] = rec["policy"], policy
    save_record(config_dir, rec)
    audit(actor, "LOCAL_ADMIN_POLICY", f"account={USER} policy={policy} was={old}", "cli")
    return {"policy": policy, "changed": True}
