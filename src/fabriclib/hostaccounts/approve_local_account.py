import datetime

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.hostaccounts.approvals import load_approvals, save_approvals
from fabriclib.hostaccounts.list_local_admins import list_local_admins


def approve_local_account(config_dir, name, actor, audit=write_audit, listed=None):
    """Purpose: a local administrator account approved as break glass by root, acting for the Enterprise Admin
             (2.1.6.78): its reminder stops, and the listing shows who approved it and when. Recorded on the host and
             audited LOCAL_ACCOUNT_APPROVE.
    Inputs:  config_dir — the install's config folder; name — the account; actor — who ran it (str); audit — the
             audit writer (tests give their own); listed — list_local_admins's result (default: read now).
    Returns: {"name", "by", "when"}.
    Fails:   ValidationError, nothing changed, for an account that is not a local administrator here (nothing to
             approve) or one already approved; ValueError, OSError from the record.
    Feeds:   run_host_command (`fabricctl host accounts approve`)."""
    rows = {r["name"]: r for r in (listed if listed is not None else list_local_admins(config_dir))}
    if name not in rows:
        raise ValidationError(f"{name} is not a local root or administrator account on this host: nothing to approve "
                              "(`fabricctl host accounts list` shows them)")
    if rows[name]["approved"]:
        raise ValidationError(f"{name} is already approved (by {rows[name]['approved'].get('by')})")
    data = load_approvals(config_dir)
    entry = {"by": actor, "when": datetime.datetime.now().isoformat(timespec="seconds")}
    data["approved"][name] = entry
    save_approvals(config_dir, data)
    audit(actor, "LOCAL_ACCOUNT_APPROVE", f"account={name} why={'; '.join(rows[name]['why'])}", "cli")
    return {"name": name, **entry}
