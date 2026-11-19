import os
import sys

from fabriclib.backup.read_backup_key import read_backup_key
from fabriclib.backup.read_build import read_build
from fabriclib.backup.read_changes import read_changes
from fabriclib.backup.restore_bundle import restore_bundle
from fabriclib.backup.restore_section import restore_section
from fabriclib.backup.sections import SECTIONS
from fabriclib.common.ask import ask
from fabriclib.common.errors import ValidationError
from fabriclib.setup.context import SetupContext
from fabriclib.setup.restore_install import restore_install

USAGE = ("usage: fabricctl restore <bundle.fabric.tar> [--set host_ip=… --set lan_cidr=… --set lan_gateway=…] "
         "[--key-file PATH | --key-stdin] [--yes] [--approve GROUPS] [--decline GROUPS]\n"
         "       fabricctl restore <export folder> [--yes] …   (a folder from 0.10.0's `fabricctl uninstall --export`)")


def _restore_bundle(args, ctx, path, cli):
    """Purpose: `fabricctl restore <bundle>` (manual 1.3.7.6, 1.3.7.7): the bundle restored whole, with any address
             changes, then setup run on it, as for an export.
    Inputs:  args — the command's arguments (--set key=value, --key-file, --key-stdin, --yes, --approve/--decline);
             ctx — SetupContext; path — the bundle; cli — the packaged cli.py setup is run with.
    Returns: 1 when refused or not confirmed; on success it does not return (setup replaces the process).
    Fails:   OSError from os.execv.
    Feeds:   run_restore_command."""
    try:
        changes = read_changes(args)
        if "--yes" not in args and "-y" not in args:
            what = ", ".join(f"{k}={v}" for k, v in changes.items()) or "no changes"
            if ask("restore.confirm_bundle", f"Restore fabric from {path} ({what}) and set it up. "
                   "Type 'yes' to continue: ").lower() != "yes":
                print("nothing changed")
                return 1
        out = restore_bundle(ctx.deploy_base, path, read_backup_key(args, {}, opening=True), changes,
                             read_build(os.path.dirname(os.path.dirname(os.path.dirname(cli))))["version"])
    except ValidationError as exc:
        print(f"error: {exc}\n{USAGE}", file=sys.stderr)
        return 1
    for key, (old, new) in out["changed"].items():
        print(f"  {key}: {old} -> {new}")
    for setting, value in out.get("leftover", []):
        print(f"  still at the old address (change it after setup): {setting} = {value}")
    consent = [x for i, a in enumerate(args) if a in ("--approve", "--decline") and i + 1 < len(args)
               for x in (a, args[i + 1])]
    os.execv(sys.executable, [sys.executable, cli, "setup", "--yes", "--non-interactive", *consent,
                              *[a for a in args if a.startswith("--deploy-base") or a == "--no-color"]])


def _restore_one_section(args, ctx, path):
    """Purpose: `fabricctl restore <bundle> --section NAME` on a running install (manual 1.3.7.8): the warning, the
             site's name typed, then restore_section (a safety bundle first).
    Inputs:  args — the command's arguments (--section NAME, --key-file, --key-stdin, --yes); ctx — SetupContext of
             the install; path — the bundle.
    Returns: 0 when restored, 1 when refused or not confirmed (the reason printed).
    Fails:   CalledProcessError from the apply that follows (printed by it).
    Feeds:   run_restore_command."""
    section = args[args.index("--section") + 1] if args.index("--section") + 1 < len(args) else ""
    try:
        if not os.path.exists(ctx.vars_file):
            raise ValidationError("fabric is not installed here: restore the whole bundle instead (no --section)")
        v = ctx.load_state().vars
        site = v.get("site_name") or v.get("hostname") or "fabric"
        what = SECTIONS[section]["what"] if section in SECTIONS else section
        print(f"Restoring {section} replaces it on this install: {what}. What it holds now is lost (a safety bundle "
              "of it is made first) and this cannot be undone."
              + (f" Depends on it: {', '.join(SECTIONS[section]['depends'])}." if section in SECTIONS
                 and SECTIONS[section]["depends"] else ""))
        if "--yes" not in args and "-y" not in args:
            if ask("restore.confirm_section", f"Type the site's name ({site}) to restore {section}: ").strip() != site:
                print("nothing changed")
                return 1
        version = read_build(ctx.target_dir)["version"]
        out = restore_section(ctx.deploy_base, ctx.config_dir, path, section,
                              read_backup_key(args, v, opening=True), version)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"{section} restored from {os.path.basename(path)}; the state it replaced is in {out['safety']}")
    return 0


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
    values = {i + 1 for i, a in enumerate(args)
              if a in ("--set", "--key-file", "--approve", "--decline", "--section")}
    folder = next((a for i, a in enumerate(args) if not a.startswith("-") and i not in values), None)
    ctx = SetupContext(deploy_base=deploy_base)
    if folder and os.path.isfile(folder) and "--section" in args:
        return _restore_one_section(args, ctx, os.path.realpath(folder))
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
