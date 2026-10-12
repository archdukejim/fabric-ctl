import os
import subprocess
import sys
import time

from fabriclib.common.ask import ask
from fabriclib.common.errors import ValidationError
from fabriclib.common.sudo_owner import sudo_owner
from fabriclib.setup.check_export_dir import check_export_dir
from fabriclib.setup.context import SetupContext
from fabriclib.setup.export_install import export_install
from fabriclib.setup.uninstall import uninstall
from fabriclib.undo.uninstall_plan import uninstall_plan

USAGE = """usage: fabricctl uninstall                      asks: export first? where? remove the package too?
       fabricctl uninstall --yes (--export DIR | --no-export) [--purge-package]"""


def _opt(args, name):
    """Purpose: the value after an option.
    Inputs:  args — argument list; name — option such as "--export".
    Returns: the next word, or None when the option is absent or last.
    Fails:   never.
    Feeds:   run_uninstall_command."""
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else None


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


def run_uninstall_command(args, deploy_base):
    """Purpose: `fabricctl uninstall`: offer to export all of fabric's data to a folder you choose, remove
             fabric, and optionally the fabricctl package too. What happens to each host change fabric made is listed
             first (undo/uninstall_plan); every question is asked before anything is touched.
    Inputs:  args — --help/-h (the usage, nothing else), --yes/-y, --export DIR, --no-export, --purge-package;
             deploy_base — install root.
             Unattended (--yes) the export choice must be explicit. Interactive otherwise.
    Returns: 0 when removed (package purge result is printed, not returned); 1 when refused or not confirmed.
             Leaves the export folder (root only) when one was chosen.
    Fails:   ValidationError (bad/missing export choice or folder from check_export_dir, or OpenBao unreachable in
             export_secrets) is printed with USAGE, exit 1, before anything is removed; CalledProcessError from
             export copying (the stack is stopped by then) and OSError from uninstall propagate; EOFError from
             input().
    Feeds:   cli main (`uninstall`); packaging/deb/postrm (apt purge: --yes --export)."""
    if "--help" in args or "-h" in args:          # never the interactive removal (it started it before, 2.3.6.1.27)
        print(USAGE)
        return 0
    ctx = SetupContext(deploy_base=deploy_base).load_state()
    export, purge = _opt(args, "--export"), "--purge-package" in args
    try:
        if "--yes" in args or "-y" in args:
            if not export and "--no-export" not in args:
                raise ValidationError("with --yes, choose --export DIR or --no-export")
            _show_plan()
        else:
            print(f"This removes fabric from this host: every service, its data, the CA and the vault "
                  f"({ctx.deploy_base}, /etc/fabric/openbao). Docker and other containers are not touched.")
            _show_plan()
            if not export and "--no-export" not in args:
                if ask("uninstall.export", "Export all of fabric's data first (config, secrets, CA, directory, "
                       "vault + key)? [Y/n] ").lower() in ("", "y", "yes"):
                    default = os.path.join(sudo_owner()[1], f"fabric-export-{time.strftime('%Y%m%d-%H%M%S')}")
                    export = ask("uninstall.export_dir", f"Export folder [{default}]: ", default)
            if export:
                export = check_export_dir(ctx, export)         # refuse before anything is touched
            if not purge and _package_installed():
                purge = ask("uninstall.purge",
                            "Also remove the fabricctl package (apt purge)? [y/N] ").lower() in ("y", "yes")
            if ask("uninstall.confirm", "Type 'yes' to remove fabric: ").lower() != "yes":
                print("nothing changed")
                return 1
        if export:
            export_install(ctx, check_export_dir(ctx, export))
        uninstall(ctx)
    except ValidationError as exc:
        print(f"error: {exc}\n{USAGE}", file=sys.stderr)
        return 1
    if purge and _package_installed():
        res = subprocess.run(["apt-get", "purge", "-y", "-q", "fabricctl"],
                             env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"})
        print("fabricctl package removed" if res.returncode == 0 else "apt purge failed: sudo apt purge fabricctl")
    if export:
        print(f"Your data is in {export} (root only). It holds your CA and opens your vault: move it offline.")
    return 0
