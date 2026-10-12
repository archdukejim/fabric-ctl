import json
import os

from fabriclib.common.errors import ValidationError
from fabriclib.consent.plan_member import RECORD
from fabriclib.directory.remove_machine import remove_machine


def remove_host_account(config_dir, v, secrets):
    """Purpose: remove the host's own computer account that fabric made in the domain (manual 1.6.11.8, decision
             2.1.6.48), as part of undoing `member` and of the uninstall, while the DC still answers. An account
             already gone is fine; one the DC refuses to remove is said, with where to remove it, and the rest of
             the undo goes on.
    Inputs:  config_dir — the install's config folder (RECORD names the account); v — vars (site_name); secrets —
             a function returning fabric's secrets (called only when there is an account to remove).
    Returns: list of str, what was done (empty when fabric made no account for this host). RECORD forgets the
             account once it is gone.
    Fails:   OSError / ValueError on a damaged RECORD.
    Feeds:   undo/undo_group (`fabricctl setup --undo member`), setup/uninstall."""
    path = os.path.join(config_dir, RECORD)
    if not os.path.exists(path):
        return []
    with open(path) as f:
        record = json.load(f)
    account = record.get("account")
    if not account:
        return []
    try:
        remove_machine(v, "fabricctl setup", account.lower(), source="setup", secrets=secrets())
        done = f"the domain: this host's computer account {account}$ removed"
    except ValidationError as e:
        if "no such entry" not in str(e):
            return [f"the domain: this host's computer account {account}$ NOT removed ({e}): remove it in the web "
                    "console (Directory → Machines)"]
        done = f"the domain: this host's computer account {account}$ was already gone"
    record["account"] = None
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f)
    return [done]
