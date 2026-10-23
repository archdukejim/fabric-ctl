import json
import os

from fabriclib.localadmin.constants import DEFAULT_POLICY, RECORD

EMPTY = {"made": False, "made_at": None, "policy": DEFAULT_POLICY, "version": None, "set_at": None, "reason": None,
         "used": None, "checkout": None, "waiting": None, "last_check": None, "ssh": None}


def load_record(config_dir):
    """Purpose: the host's record of its local-admin (manual 1.7.1.4): whether fabric made the account, its policy, the
             version OpenBao holds as current and when it was set, a use or check-out seen since, a rotation waiting,
             the last timer run and the SSH switch as applied. Never a password.
    Inputs:  config_dir — the install's config folder (<config>/local-admin.json).
    Returns: dict with every key of EMPTY (a missing record: EMPTY, nothing made).
    Fails:   ValueError for a record that is not JSON (never guessed); OSError other than a missing file.
    Feeds:   every function of fabriclib/localadmin, hostaccounts/list_local_admins, system/relaxed_settings."""
    try:
        with open(os.path.join(config_dir, RECORD)) as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}
    return {**EMPTY, **{k: v for k, v in data.items() if k in EMPTY}}


def save_record(config_dir, data):
    """Purpose: the record written whole (0600, replaced atomically).
    Inputs:  config_dir — the install's config folder; data — as load_record returns it.
    Returns: None.
    Fails:   OSError when it cannot be written.
    Feeds:   every function of fabriclib/localadmin that changes something."""
    path = os.path.join(config_dir, RECORD)
    fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.replace(path + ".new", path)
