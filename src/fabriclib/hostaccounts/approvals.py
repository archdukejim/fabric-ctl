import json
import os

from fabriclib.hostaccounts.constants import RECORD


def load_approvals(config_dir):
    """Purpose: the host's record of its local administrator accounts (2.1.6.78): the account that ran setup and the
             accounts the Enterprise Admin approved as break glass.
    Inputs:  config_dir — the install's config folder (<config>/local-accounts.json).
    Returns: {"setup_user": str or None, "approved": {name: {"by", "when"}}}; empty when there is no record yet.
    Fails:   ValueError for a record that is not JSON (never guessed: an approval is the Enterprise Admin's); OSError
             other than a missing file.
    Feeds:   list_local_admins, approve_local_account, unapprove_local_account, record_setup_user."""
    try:
        with open(os.path.join(config_dir, RECORD)) as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}
    return {"setup_user": data.get("setup_user"), "approved": dict(data.get("approved") or {})}


def save_approvals(config_dir, data):
    """Purpose: the record written whole (0600, replaced atomically).
    Inputs:  config_dir — the install's config folder; data — as load_approvals returns it.
    Returns: None.
    Fails:   OSError when the record cannot be written.
    Feeds:   approve_local_account, unapprove_local_account, record_setup_user."""
    path = os.path.join(config_dir, RECORD)
    fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.replace(path + ".new", path)
