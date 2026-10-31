import getpass
import os

from fabriclib.common.errors import ValidationError
from fabriclib.hostaccounts.approve_local_account import approve_local_account
from fabriclib.hostaccounts.list_local_admins import list_local_admins
from fabriclib.hostaccounts.unapprove_local_account import unapprove_local_account

USAGE = """usage: sudo fabricctl host accounts list              this host's local root and administrator accounts
                                                    OpenBao does not manage: why each is one, approved or not
       sudo fabricctl host accounts approve <name>     approved as break glass, for the Enterprise Admin (audited):
                                                    its reminder stops
       sudo fabricctl host accounts unapprove <name>   the approval withdrawn (audited): reminded again
  As root only (manual 4.6.9)."""


def run_host_command(config_dir, args):
    """Purpose: `fabricctl host accounts …` (manual 4.6.9; 2.1.6.78): only parses and routes to the listing, the
             approval and its withdrawal.
    Inputs:  config_dir — the install's config folder; args — list of str after `host`.
    Returns: exit status: 0 done, 1 refused (said why), 2 usage.
    Fails:   OSError, ValueError from the files or the record (propagate).
    Feeds:   cli.main (which refuses anyone but root first)."""
    actor = os.environ.get("SUDO_USER") or getpass.getuser()
    if args == ["accounts", "list"]:
        rows = list_local_admins(config_dir)
        if not rows:
            print("no local root or administrator account but root")
        for r in rows:
            state = ("managed by OpenBao (local-admin, manual 1.7.1.4)" if r.get("managed") else
                     f"approved by {r['approved'].get('by')} on {r['approved'].get('when')}" if r["approved"]
                     else "not approved: reminded")
            print(f"{r['name']}{' (ran setup)' if r['setup'] else ''}: {', '.join(r['why'])}; {state}")
        return 0
    if len(args) == 3 and args[0] == "accounts" and args[1] in ("approve", "unapprove") and args[2]:
        try:
            if args[1] == "approve":
                done = approve_local_account(config_dir, args[2], actor)
                print(f"{args[2]} approved as break glass by {done['by']}: no more reminders while it stays so")
            else:
                unapprove_local_account(config_dir, args[2], actor)
                print(f"{args[2]}: approval withdrawn; reminded again while it is a local administrator")
        except ValidationError as e:
            print(f"refused: {e}")
            return 1
        return 0
    print(USAGE)
    return 2
