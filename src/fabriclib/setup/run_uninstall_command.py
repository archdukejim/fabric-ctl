import os
import subprocess
import sys

from fabriclib.backup.make_backup import make_backup
from fabriclib.backup.read_backup_key import read_backup_key
from fabriclib.common.ask import ask
from fabriclib.common.console import ok, warn
from fabriclib.common.errors import ValidationError
from fabriclib.setup.context import SetupContext
from fabriclib.setup.uninstall import uninstall
from fabriclib.undo.remove_host_account import remove_host_account
from fabriclib.undo.uninstall_plan import uninstall_plan

USAGE = """usage: fabricctl uninstall                      asks: a backup bundle first? its passphrase? the package too?
       fabricctl uninstall --yes (--backup [--key-stdin | --public-key age1… | --scheduled-key] | --no-backup)
                           [--purge-package]
       (--export DIR and --no-export are 0.10.0's names for --backup and --no-backup; the bundle goes to
        /var/backups/fabric/)"""


def _package_installed():
    """Purpose: whether the fabricctl .deb is installed.
    Inputs:  none (runs dpkg-query).
    Returns: True when dpkg reports "install ok installed" for fabricctl.
    Fails:   FileNotFoundError without dpkg-query.
    Feeds:   run_uninstall_command."""
    res = subprocess.run(["dpkg-query", "-W", "-f=${Status}", "fabricctl"], capture_output=True, text=True)
    return res.returncode == 0 and "install ok installed" in res.stdout


def _show_plan():
    """Purpose: print what uninstall does with each kind of host change fabric made, before anything is asked.
    Inputs:  none (undo/uninstall_plan).
    Returns: None.
    Fails:   never.
    Feeds:   run_uninstall_command."""
    print("Changes fabric made to this host:")
    for title, how, what in uninstall_plan():
        print(f"  {title:<24} {how:<8} {what}")


def _choice(args):
    """Purpose: the backup choice on the command line, 0.10.0's names included (manual 1.3.7.13).
    Inputs:  args — argument list.
    Returns: True (--backup, or --export DIR), False (--no-backup, --no-export), or None when not given.
    Fails:   never.
    Feeds:   run_uninstall_command."""
    if "--export" in args:
        warn("--export is now --backup: an encrypted bundle in /var/backups/fabric/ (the folder given is not used)")
    if "--backup" in args or "--export" in args:
        return True
    return False if ("--no-backup" in args or "--no-export" in args) else None


def run_uninstall_command(args, deploy_base):
    """Purpose: `fabricctl uninstall` (manual 1.3.7.13, 3.2.4): a cold backup bundle of all of fabric first (default
             yes, 1.3.7.4), then fabric removed, and optionally the fabricctl package too. With a bundle, the host's
             own computer account (1.6.11.8) is removed before the bundle stops the stack, since it needs OpenBao and
             the DC. What happens to each host change fabric made is listed first (undo/uninstall_plan); every
             question, the bundle's passphrase among them, is asked before anything is touched.
    Inputs:  args — --help/-h (the usage, nothing else), --yes/-y, --backup / --no-backup (or 0.10.0's --export DIR
             / --no-export), how the bundle is sealed (--key-stdin, --public-key, --scheduled-key; else a passphrase
             asked twice), --purge-package; deploy_base — install root.
             Unattended (--yes) the backup choice must be explicit. Interactive otherwise.
    Returns: 0 when removed (package purge result is printed, not returned); 1 when refused or not confirmed.
             Leaves the bundle in /var/backups/fabric/ (root only) when one was made.
    Fails:   ValidationError (a missing backup choice, a passphrase refused, the bundle not made: no room, OpenBao
             unreachable, the stop failing) is printed with USAGE, exit 1, with fabric not removed; OSError from
             uninstall propagates; EOFError from input().
    Feeds:   cli main (`uninstall`); packaging/deb/postrm (apt purge: --yes --backup --scheduled-key)."""
    if "--help" in args or "-h" in args:          # never the interactive removal (it started it before, 2.3.6.1.27)
        print(USAGE)
        return 0
    ctx = SetupContext(deploy_base=deploy_base).load_state()
    backup, purge, key = _choice(args), "--purge-package" in args, None
    try:
        if "--yes" in args or "-y" in args:
            if backup is None:
                raise ValidationError("with --yes, choose --backup or --no-backup")
            _show_plan()
        else:
            print(f"This removes fabric from this host: every service, its data, the CA and the vault "
                  f"({ctx.deploy_base}, /etc/fabric/openbao). Docker and other containers are not touched.")
            _show_plan()
            if backup is None:
                backup = ask("uninstall.backup", "Make an encrypted backup bundle of all of fabric first (config, "
                             "CA, directory, DNS, sign-in, vault)? [Y/n] ").lower() in ("", "y", "yes")
            if not purge and _package_installed():
                purge = ask("uninstall.purge",
                            "Also remove the fabricctl package (apt purge)? [y/N] ").lower() in ("y", "yes")
        if backup:
            key = read_backup_key(args, ctx.vars, opening=False)    # asked before anything is touched
        if "--yes" not in args and "-y" not in args:
            if ask("uninstall.confirm", "Type 'yes' to remove fabric: ").lower() != "yes":
                print("nothing changed")
                return 1
        bundle = None
        if backup:
            # the bundle stops the stack; the host's computer account needs OpenBao and the DC, so it goes first
            for line in remove_host_account(ctx.config_dir, ctx.vars, lambda: ctx.secrets):
                (warn if "NOT removed" in line else ok)(line)
            try:
                bundle = make_backup(ctx.deploy_base, ctx.vars, ctx.secrets_file, "uninstall", "cold", **key)
            except ValidationError as exc:
                raise ValidationError(f"{exc}. Fabric is not removed; if it was stopped for the copy, "
                                      "`sudo fabricctl start` starts it again") from exc
        uninstall(ctx, host_account=not backup)
    except ValidationError as exc:
        print(f"error: {exc}\n{USAGE}", file=sys.stderr)
        return 1
    if purge and _package_installed():
        res = subprocess.run(["apt-get", "purge", "-y", "-q", "fabricctl"],
                             env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"})
        print("fabricctl package removed" if res.returncode == 0 else "apt purge failed: sudo apt purge fabricctl")
    if bundle:
        print(f"Your backup is {bundle} (root only, encrypted). Restore it with `sudo fabricctl restore {bundle}`; "
              "keep a copy off this host.")
    return 0
