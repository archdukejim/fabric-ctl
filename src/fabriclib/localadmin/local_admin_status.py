from fabriclib.common.errors import ValidationError
from fabriclib.localadmin.common.account_exists import account_exists
from fabriclib.localadmin.common.rotation_due import rotation_due
from fabriclib.localadmin.read_ssh_switch import read_ssh_switch
from fabriclib.localadmin.record import load_record


def local_admin_status(v, config_dir, read_switch=read_ssh_switch, exists=account_exists):
    """Purpose: what `fabricctl local-admin status` shows (manual 1.7.1.4.7): the account, its policy, the current
             version and when it was set, a use or check-out seen and when the rotation is due, a rotation waiting,
             the SSH switch in the domain and as applied, the last timer run. Never a password.
    Inputs:  v — rendered vars; config_dir — the install's config folder; read_switch, exists — the parts (tests give
             their own).
    Returns: dict: the record's keys, "account" (bool), "due" (ISO str or None), "due_why", "domain_ssh" ({"ssh", "by",
             "when"} or {"error"}).
    Fails:   ValueError, OSError from the record.
    Feeds:   run_local_admin_command (`fabricctl local-admin status`)."""
    rec = load_record(config_dir)
    due, why = rotation_due(rec)
    try:
        switch = read_switch(v)
    except ValidationError as e:
        switch = {"error": str(e)}
    return {**rec, "account": exists(), "due": due.isoformat() if due else None, "due_why": why,
            "domain_ssh": switch}
