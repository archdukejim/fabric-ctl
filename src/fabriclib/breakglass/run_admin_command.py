import getpass
import os

from fabriclib.breakglass.reset_break_glass import reset_break_glass
from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import INSTALL_DIR

USAGE = """usage: sudo fabricctl admin reset-break-glass   fabric-admin's lost password replaced (a new generated one,
           written once to ~/fabric-admin/ of the person running sudo) and the account unlocked; on a host with a
           writable domain controller, as root (manual 4.6.9)"""


def run_admin_command(v, args, config_dir=None):
    """Purpose: `fabricctl admin …` (manual 4.6.9): only parses and routes to reset_break_glass, and says where the
             new password was written (never the password).
    Inputs:  v — rendered vars; args — list of str after `admin`; config_dir — the install's config folder (default
             <INSTALL_DIR>/config).
    Returns: exit status: 0 reset, 1 refused (said why: a read-only DC, no domain, the DC refusing or not running),
             2 usage.
    Fails:   OSError when the file cannot be written (propagates: the password is set, so run it again).
    Feeds:   cli.main (which refuses anyone but root first)."""
    if args != ["reset-break-glass"]:
        print(USAGE)
        return 2
    try:
        done = reset_break_glass(v, config_dir or os.path.join(INSTALL_DIR, "config"),
                                 os.environ.get("SUDO_USER") or getpass.getuser())
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    for line in done["changed"]:
        print(f"  {line}")
    if done["disabled"]:
        print("  fabric-admin is disabled in the directory: fabric never enables it; an Enterprise Admin decides")
    print(f"fabric-admin's new password is in {done['path']} (only there): store it, then delete the file")
    return 0
