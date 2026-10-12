import os
import sys

from fabriclib.common.ask import ask
from fabriclib.common.errors import ValidationError
from fabriclib.setup.context import SetupContext
from fabriclib.setup.restore_install import restore_install

USAGE = ("usage: fabricctl restore <export folder> [--yes] [--approve GROUPS] [--decline GROUPS]   "
         "(a folder written by `fabricctl uninstall --export`)")


def run_restore_command(args, deploy_base, cli):
    """Purpose: `fabricctl restore <folder>`: bring back a fabric removed with `fabricctl uninstall --export` (or
             apt purge): its data goes back in place with owners and modes, then setup runs on it — the same CA,
             directory, Keycloak, DNS and vault (its key comes back with it).
    Inputs:  args — command arguments: the export folder (first non-option), --yes/-y, --deploy-base, --no-color,
             --approve/--decline GROUPS (passed to setup: the export's recorded answers usually cover everything);
             deploy_base — install root; cli — path of this fabricctl's cli.py (the packaged, newest code) that
             setup is run with.
    Returns: 1 when refused (no folder, not an export, fabric already installed) or not confirmed; on success
             it does not return: restore_install, then the process is replaced by
             `cli.py setup --yes --non-interactive`.
    Fails:   ValidationError is printed with USAGE (exit 1); CalledProcessError from restore_install (cp -a);
             EOFError from input() without --yes; OSError from os.execv.
    Feeds:   cli main (`restore`)."""
    folder = next((a for a in args if not a.startswith("-")), None)
    ctx = SetupContext(deploy_base=deploy_base)
    try:
        if not folder:
            raise ValidationError("which export folder?")
        folder = os.path.realpath(folder)
        if not (os.path.isfile(os.path.join(folder, "README.txt"))
                and os.path.isfile(os.path.join(folder, "fabric", "config", "vars.yaml"))):
            raise ValidationError(f"{folder} is not a fabric export (no README.txt / fabric/config/vars.yaml)")
        if os.path.exists(ctx.vars_file):
            raise ValidationError(f"fabric is installed here ({ctx.vars_file}): run `sudo fabricctl uninstall` first")
    except ValidationError as exc:
        print(f"error: {exc}\n{USAGE}", file=sys.stderr)
        return 1
    if "--yes" not in args and "-y" not in args:
        if ask("restore.confirm",
               f"Restore fabric from {folder} and set it up. Type 'yes' to continue: ").lower() != "yes":
            print("nothing changed")
            return 1
    restore_install(ctx, folder)
    consent = [x for i, a in enumerate(args) if a in ("--approve", "--decline") and i + 1 < len(args)
               for x in (a, args[i + 1])]          # host changes the restored answers do not cover yet
    os.execv(sys.executable, [sys.executable, cli, "setup", "--yes", "--non-interactive", *consent,
                              *[a for a in args if a.startswith("--deploy-base") or a == "--no-color"]])
