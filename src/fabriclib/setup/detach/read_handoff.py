import os
import stat

import yaml

from fabriclib.setup.errors import SetupError


def read_handoff(path, owner=0):
    """Purpose: the secrets setup's questions handed to its unit (manual 1.3.2.3.4), read once: the file is removed
             before they are used, whatever is in it.
    Inputs:  path — the hand-off file (write_handoff); owner — the uid it must belong to (root; tests give their
             own).
    Returns: {name: str} (empty when the file holds nothing).
    Fails:   SetupError, after removing the file when it is there, for one that is a symlink or not a regular file,
             not owned by owner, readable or writable by anyone else (not 0600 or stricter), or not a mapping;
             SetupError when it is missing (the run was already started once: run setup again).
    Feeds:   detach/run_worker."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise SetupError(f"the secrets handed to this run are gone ({path}): it was started already; run "
                         "`sudo fabricctl setup` again") from None
    try:
        if not stat.S_ISREG(st.st_mode) or st.st_uid != owner or st.st_mode & 0o077:
            raise SetupError(f"refused {path}: not a regular file of uid {owner} with mode 0600")
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    finally:
        os.remove(path)
    if not isinstance(data, dict):
        raise SetupError(f"refused {path}: not the secrets setup hands over")
    return {str(k): str(v) for k, v in data.items() if v is not None}
