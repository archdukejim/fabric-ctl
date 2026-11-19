import os
import sys

from fabriclib.backup.read_backup_key import read_backup_key
from fabriclib.backup.restore_bundle import restore_bundle
from fabriclib.common.ask import ask
from fabriclib.common.errors import ValidationError
from fabriclib.setup.context import SetupContext
from fabriclib.setup.restore_install import restore_install

USAGE = ("usage: fabricctl restore <bundle.fabric.tar> [--set host_ip=… --set lan_cidr=… --set lan_gateway=…] "
         "[--key-file PATH | --key-stdin] [--yes] [--approve GROUPS] [--decline GROUPS]\n"
         "       fabricctl restore <export folder> [--yes] …   (a folder from 0.10.0's `fabricctl uninstall --export`)")


def _package_version(cli):
    """Purpose: the installed package's version, from the BUILD file beside the packaged code.
    Inputs:  cli — path of the packaged cli.py.
    Returns: str, "?" when unknown.
    Fails:   never.
    Feeds:   _restore_bundle."""
    try:
        with open(os.path.join(os.path.dirname(os.path.dirname(cli)), "fabric", "BUILD")) as f:
            line = next((x for x in f if x.startswith("package:")), "")
        return line.split()[-1] if line else "?"
    except OSError:
        return "?"


def _restore_bundle(args, ctx, path, cli):
    """Purpose: `fabricctl restore <bundle>` (manual 1.3.7.6, 1.3.7.7): the bundle restored whole, with any address
             changes, then setup run on it, as for an export.
    Inputs:  args — the command's arguments (--set key=value, --key-file, --key-stdin, --yes, --approve/--decline);
             ctx — SetupContext; path — the bundle; cli — the packaged cli.py setup is run with.
    Returns: 1 when refused or not confirmed; on success it does not return (setup replaces the process).
    Fails:   OSError from os.execv.
    Feeds:   run_restore_command."""
    changes = {}
    try:
        for i, a in enumerate(args):
            if a == "--set":
                key, sep, value = (args[i + 1] if i + 1 < len(args) else "").partition("=")
                if not sep:
                    raise ValidationError("--set takes key=value, for example --set host_ip=10.0.5.2")
                changes[key] = value
        if "--yes" not in args and "-y" not in args:
            what = ", ".join(f"{k}={v}" for k, v in changes.items()) or "no changes"
            if ask("restore.confirm_bundle", f"Restore fabric from {path} ({what}) and set it up. "
                   "Type 'yes' to continue: ").lower() != "yes":
                print("nothing changed")
                return 1
        out = restore_bundle(ctx.deploy_base, path, read_backup_key(args, {}, opening=True), changes,
                             _package_version(cli))
    except ValidationError as exc:
        print(f"error: {exc}\n{USAGE}", file=sys.stderr)
        return 1
    for key, (old, new) in out["changed"].items():
        print(f"  {key}: {old} -> {new}")
    consent = [x for i, a in enumerate(args) if a in ("--approve", "--decline") and i + 1 < len(args)
               for x in (a, args[i + 1])]
    os.execv(sys.executable, [sys.executable, cli, "setup", "--yes", "--non-interactive", *consent,
                              *[a for a in args if a.startswith("--deploy-base") or a == "--no-color"]])


def run_restore_command(args, deploy_base, cli):
    """Purpose: `fabricctl restore <bundle>` (1.3.7.6, _restore_bundle), or `fabricctl restore <folder>`: bring
             back a fabric removed with 0.10.0's `fabricctl uninstall --export` (or apt purge): its data goes back in
             place with owners and modes, then setup runs on it — the same CA, directory, Keycloak, DNS and vault
             (its key comes back with it).
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
    values = {i + 1 for i, a in enumerate(args) if a in ("--set", "--key-file", "--approve", "--decline")}
    folder = next((a for i, a in enumerate(args) if not a.startswith("-") and i not in values), None)
    ctx = SetupContext(deploy_base=deploy_base)
    if folder and os.path.isfile(folder):
        return _restore_bundle(args, ctx, os.path.realpath(folder), cli)
    try:
        if not folder:
            raise ValidationError("which bundle or export folder?")
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
