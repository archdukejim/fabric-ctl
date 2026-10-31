from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.hostaccounts.approvals import load_approvals, save_approvals


def unapprove_local_account(config_dir, name, actor, audit=write_audit):
    """Purpose: an approval withdrawn by root, acting for the Enterprise Admin (2.1.6.78): the account is reminded of
             again while it is a local administrator. Audited LOCAL_ACCOUNT_UNAPPROVE. Works for an account no longer
             on the host too (its stale approval goes).
    Inputs:  config_dir — the install's config folder; name — the account; actor — who ran it (str); audit — the
             audit writer (tests give their own).
    Returns: {"name", "was": the approval withdrawn}.
    Fails:   ValidationError, nothing changed, for an account that is not approved; ValueError, OSError from the
             record.
    Feeds:   run_host_command (`fabricctl host accounts unapprove`)."""
    data = load_approvals(config_dir)
    was = data["approved"].pop(name, None)
    if not was:
        raise ValidationError(f"{name} is not approved: nothing to withdraw")
    save_approvals(config_dir, data)
    audit(actor, "LOCAL_ACCOUNT_UNAPPROVE", f"account={name} approved_by={was.get('by')}", "cli")
    return {"name": name, "was": was}
