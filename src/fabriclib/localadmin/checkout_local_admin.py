from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.localadmin.common.account_exists import account_exists
from fabriclib.localadmin.common.local_admin_token import local_admin_token
from fabriclib.localadmin.common.rotation_due import rotation_due
from fabriclib.localadmin.common.utc_now import utc_now
from fabriclib.localadmin.constants import REASON_MAX, USER
from fabriclib.localadmin.read_local_admin_secret import read_local_admin_secret
from fabriclib.localadmin.record import load_record, save_record
from fabriclib.localadmin.require_enterprise_admin import require_enterprise_admin


def checkout_local_admin(v, config_dir, caller, actor, reason, source="cli", token_fn=None,
                         audit=write_audit, container="samba", now=utc_now):
    """Purpose: the host's local-admin password checked out (decision 2.1.7.18, manual 1.7.1.4.5): only by the
             Enterprise Admin's tier, with a reason; read from OpenBao (audited there too), audited
             LOCAL_ADMIN_CHECKOUT (never the password), and the password marked for rotation after use.
    Inputs:  v — rendered vars; config_dir — the install's config folder; caller — the signed-in person (None: root
             on the host); actor — who, for the audit; reason — str; source — "cli" or "web"; token_fn — how
             OpenBao is asked (None: local_admin_token); audit — write_audit; container — the DC's container; now — the
             clock (tests give their own).
    Returns: {"password", "version", "rotates_after": ISO str, "reason"}.
    Fails:   ValidationError, nothing recorded: a caller below the Enterprise Admin; no reason, one of more than
             REASON_MAX characters or more than one line; no local-admin fabric made on this host; OpenBao locked or
             holding no current password.
    Feeds:   run_local_admin_command (`fabricctl local-admin checkout`), agent/post_local_admin (POST
             /v1/local-admin/checkout)."""
    require_enterprise_admin(v, caller, "check out local-admin's password", container)
    reason = (reason or "").strip()
    if not reason:
        raise ValidationError("a check-out needs a reason (--reason \"why\"): it is audited (1.7.1.3.5)")
    if len(reason) > REASON_MAX or "\n" in reason or "\r" in reason:
        raise ValidationError(f"the reason: one line of up to {REASON_MAX} characters")
    rec = load_record(config_dir)
    if not rec["made"] or not account_exists():
        raise ValidationError("this host has no local-admin made by fabric (the `local_admin` host change: `sudo "
                              "fabricctl setup --step localadmin`)")
    token, why = (token_fn or local_admin_token)(v)
    if token is None:
        raise ValidationError(f"{why}: the password is only in OpenBao; unlock it first (manual 4.7.1.3)")
    secret = read_local_admin_secret(v, token, password=True)
    stamp = now().isoformat()
    if not rec["checkout"]:                  # the first check-out of this password starts its grace
        rec["checkout"] = {"by": actor, "when": stamp, "reason": reason, "source": source}
    save_record(config_dir, rec)
    due, _ = rotation_due(rec)
    audit(actor, "LOCAL_ADMIN_CHECKOUT", f"account={USER} version={secret['current']} reason={reason} "
                                         f"rotates_after={due.isoformat()}", source)
    return {"password": secret["password"], "version": secret["current"], "rotates_after": due.isoformat(),
            "reason": reason}
