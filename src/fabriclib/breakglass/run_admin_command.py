import getpass
import os

from fabriclib.breakglass.rename_host import rename_host
from fabriclib.breakglass.reset_break_glass import reset_break_glass
from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import INSTALL_DIR

USAGE = """usage: sudo fabricctl admin reset-break-glass   fabric-admin's lost password replaced (a new generated one,
           written once to ~/fabric-admin/ of the person running sudo), a lockout left to run out (when it ends said);
           on a host with a writable domain controller, as root (manual 4.6.9)
       sudo fabricctl admin rename-host <new-name> --reason "<why>"   a domain controller's host renamed, the only
           way (2.1.6.104): the host's name, vars.yaml and the name an apply holds it to, its local-admin under the
           new name; then the apply and the member step (manual 4.2.4.3)"""


def _reset(v, config_dir, actor):
    """Purpose: `fabricctl admin reset-break-glass`: the reset, and where the new password was written (never it).
    Inputs:  v — rendered vars; config_dir — the install's config folder; actor — the person behind sudo.
    Returns: exit status: 0 reset, 1 refused.
    Fails:   OSError when the file cannot be written (propagates: the password is set, so run it again).
    Feeds:   run_admin_command."""
    try:
        done = reset_break_glass(v, config_dir, actor)
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    for line in done["changed"]:
        print(f"  {line}")
    if done["locked_until"]:
        print(f"  fabric-admin is locked out until {done['locked_until']} (UTC): the new password works from then; "
              "the reset never shortens a lockout (2.1.6.92)")
    if done["disabled"]:
        print("  fabric-admin is disabled in the directory: fabric never enables it; an Enterprise Admin decides")
    print(f"fabric-admin's new password is in {done['path']} (only there): store it, then delete the file")
    return 0


def _rename(v, config_dir, actor, args):
    """Purpose: `fabricctl admin rename-host <new-name> --reason "<why>"`: the break-glass rename, what it changed,
             and the two steps that follow it.
    Inputs:  v — rendered vars; config_dir — the install's config folder; actor — the person behind sudo; args — the
             arguments after `rename-host`.
    Returns: exit status: 0 renamed, 1 refused or stopped part-way (said why), 2 usage.
    Fails:   OSError writing (propagates).
    Feeds:   run_admin_command."""
    if len(args) != 3 or args[1] != "--reason" or args[0].startswith("-"):
        print(USAGE)
        return 2
    try:
        done = rename_host(v, config_dir, args[0], args[2], actor)
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    for line in done["changed"]:
        print(f"  {line}")
    print(f"renamed {done['from']} to {done['to']} (audited HOST_RENAME). Next, manual 4.2.4.3: `sudo fabricctl "
          "--apply`, then `sudo fabricctl setup --step member --non-interactive --approve member`")
    return 0


def run_admin_command(v, args, config_dir=None):
    """Purpose: `fabricctl admin …` (manual 4.6.9): the break-glass commands, only parsed and routed: the reset of
             fabric-admin's password (reset_break_glass) and a domain controller's host renamed (rename_host,
             2.1.6.104).
    Inputs:  v — rendered vars; args — list of str after `admin`; config_dir — the install's config folder (default
             <INSTALL_DIR>/config).
    Returns: exit status: 0 done, 1 refused (said why), 2 usage.
    Fails:   OSError when a file cannot be written (propagates).
    Feeds:   cli.main (which refuses anyone but root first)."""
    config_dir = config_dir or os.path.join(INSTALL_DIR, "config")
    actor = os.environ.get("SUDO_USER") or getpass.getuser()
    if args == ["reset-break-glass"]:
        return _reset(v, config_dir, actor)
    if args[:1] == ["rename-host"]:
        return _rename(v, config_dir, actor, args[1:])
    print(USAGE)
    return 2
