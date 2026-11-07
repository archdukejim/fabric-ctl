import copy
import os
import threading
import time

import yaml

from fabriclib.common.paths import VARS_FILE

SETTLED_SECONDS = 2     # a file written just now could change again with the same time and size: not kept yet
_lock = threading.Lock()
_held = {}          # path -> (the file's mtime, size and inode, what it held)


def load_vars(path=VARS_FILE):
    """Purpose: read vars.yaml. It is parsed again only when the file changed (about 26 ms each time on the test Pi, and
             several times a request, decision 2.1.8.35).
    Inputs:  path — str, default VARS_FILE (<fabric>/config/vars.yaml).
    Returns: dict of the settings, the caller's own to change; {} if the file does not exist or is empty.
    Fails:   yaml.YAMLError on invalid YAML; OSError (e.g. PermissionError) if it cannot be read.
    Feeds:   dns/*, dhcp/add_reservation, dhcp/remove_reservation, radius/* (client and group edits),
             secrets/load_secrets, secrets/save_secrets, agent/ (fabric-agent), menu/ (the vars editor)."""
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        st = os.fstat(f.fileno())
        same = (st.st_mtime_ns, st.st_size, st.st_ino)
        with _lock:
            kept = _held.get(path)
        if kept and kept[0] == same:
            return copy.deepcopy(kept[1])
        value = yaml.safe_load(f) or {}
    if time.time() - st.st_mtime > SETTLED_SECONDS:
        with _lock:
            _held[path] = (same, value)
    return copy.deepcopy(value)
