import grp
import os
import pwd

from fabriclib.setup.errors import SetupError
from fabriclib.setup.site.constants import SITE_ID


def site_account(number=SITE_ID, proc="/proc"):
    """Purpose: check the user number the setup site's listener runs as is nobody's (manual 1.3.6.7, decision 2.1.8.61):
             no account, no group and no running process holds it, so nothing else on the host shares its rights.
    Inputs:  number — the uid and gid; proc — where the processes are (tests give their own).
    Returns: number.
    Fails:   SetupError naming what holds it, offering --terminal. Nothing is changed.
    Feeds:   setup/site/guided_site."""
    held = []
    try:
        held.append(f"the account {pwd.getpwuid(number).pw_name}")
    except KeyError:
        pass
    try:
        held.append(f"the group {grp.getgrgid(number).gr_name}")
    except KeyError:
        pass
    for pid in filter(str.isdigit, os.listdir(proc)):
        try:
            with open(os.path.join(proc, pid, "status")) as f:
                ids = next((line.split()[1:] for line in f if line.startswith("Uid:")), [])
        except OSError:                  # a process that ended while it was read holds nothing
            continue
        if str(number) in ids:
            held.append(f"process {pid}")
    if held:
        raise SetupError(f"web-guided setup runs its site as user number {number}, which must be nobody else's, and "
                         f"{', '.join(held[:5])} holds it here. Run Guided here instead: sudo fabricctl setup "
                         "--terminal. Nothing was changed.")
    return number
