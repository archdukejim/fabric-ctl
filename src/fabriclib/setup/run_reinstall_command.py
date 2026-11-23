import getpass
import os
import sys

from fabriclib.backup.check_changes import NETWORK, check_changes
from fabriclib.backup.check_whole_restore import check_whole_restore
from fabriclib.backup.make_backup import make_backup
from fabriclib.backup.read_backup_key import read_backup_key
from fabriclib.backup.read_build import read_build
from fabriclib.backup.read_changes import read_changes
from fabriclib.backup.restore_bundle import restore_bundle
from fabriclib.common.ask import ask
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.ipam.kept_plan_subnets import kept_plan_subnets
from fabriclib.setup.common.address_in_use import address_in_use
from fabriclib.setup.common.network_problem import network_problem
from fabriclib.setup.context import SetupContext
from fabriclib.setup.stage_source import stage_source
from fabriclib.setup.uninstall import uninstall

USAGE = ("usage: fabricctl reinstall [--set host_ip=… --set lan_cidr=… --set lan_gateway=…] [--key-stdin] [--yes] "
         "[setup options]\n       fabricctl reinstall --from <bundle> [--key-file PATH | --key-file-once PATH | "
         "--key-stdin] [--yes] [setup options]")
OWN = ("--yes", "-y", "--key-stdin", "--set", "--from", "--key-file", "--key-file-once")
VALUED = ("--set", "--from", "--key-file", "--key-file-once")


def _setup_args(args):
    """Purpose: the arguments reinstall passes on to setup: everything but its own (and --set's values).
    Inputs:  args — the command's arguments.
    Returns: list of str.
    Fails:   never.
    Feeds:   run_reinstall_command."""
    values = {i + 1 for i, a in enumerate(args) if a in VALUED}
    return [a for i, a in enumerate(args) if a not in OWN and i not in values]


def _reinstall_from(args, ctx):
    """Purpose: `fabricctl reinstall --from <bundle>` (manual 1.3.7.9, the console's whole restore): that bundle
             restored whole and unchanged in place of the running install, after a safety bundle of the install as it
             is (cold, sealed as the chosen bundle is: the same passphrase, or the public key it was made to).
    Inputs:  args — --from FILE, --key-file / --key-file-once / --key-stdin (what opens it), --yes, setup's options;
             ctx — SetupContext, loaded. The actor is FABRIC_ACTOR when fabric-agent starts it, else the user.
    Returns: 1 when refused or not confirmed (nothing touched); on success it does not return (setup replaces the
             process).
    Fails:   ValidationError printed (exit 1): --set given too, a bundle check_whole_restore refuses (before anything
             is stopped), the safety bundle not made; after the uninstall, the restore failing (both bundles named);
             OSError from os.execv.
    Feeds:   run_reinstall_command."""
    v, actor = ctx.vars, os.environ.get("FABRIC_ACTOR") or getpass.getuser()
    try:
        if "--set" in args:
            raise ValidationError("--from restores the bundle unchanged: a move is manual 4.2.4.8")
        at = args.index("--from") + 1
        if at >= len(args) or args[at].startswith("-"):
            raise ValidationError("--from needs a bundle")
        path = os.path.realpath(args[at])
        key = read_backup_key(args, v, opening=True)
        source = stage_source(ctx)                       # uninstall deletes an installed copy
        cli = os.path.join(source, "lib", "fabriclib", "cli.py")
        version = read_build(source)["version"]
        manifest = check_whole_restore(ctx.deploy_base, path, key, version)
        print(f"Restore {os.path.basename(path)} (made {manifest.get('made')}) in place of this install: a safety "
              "bundle of it first, then fabric is removed, the bundle restored and set up.")
        if "--yes" not in args and "-y" not in args:
            if ask("cli.reinstall.confirm", "Type 'yes' to continue: ").lower() != "yes":
                print("nothing changed")
                return 1
        opened_by = manifest.get("opened_by") or "passphrase"
        seal = ({"passphrase": key["passphrase"], "public_key": None} if key.get("passphrase") is not None
                else {"passphrase": None, "public_key": opened_by})
        if seal["public_key"] is not None and not str(seal["public_key"]).startswith("age1"):
            raise ValidationError("the bundle opened with a private key names no public key to seal the safety "
                                  "bundle with")
        safety = make_backup(ctx.deploy_base, v, ctx.secrets_file, "reinstall", "cold", actor=actor, **seal)
    except ValidationError as exc:
        print(f"error: {exc}\n{USAGE}", file=sys.stderr)
        return 1
    print(f"safety bundle: {safety}")
    uninstall(ctx, host_account=False)
    try:
        restore_bundle(ctx.deploy_base, path, key, {}, version, actor=actor)
    except ValidationError as exc:
        print(f"error: the restore did not finish: {exc}\nFabric is removed. `sudo fabricctl restore {path}` tries "
              f"again; `sudo fabricctl restore {safety}` puts back the install as it was.", file=sys.stderr)
        return 1
    write_audit(actor, "RESTORE_WHOLE", f"bundle={os.path.basename(path)} safety={os.path.basename(safety)}",
                source="web" if os.environ.get("FABRIC_ACTOR") else "cli")
    os.execv(sys.executable, [sys.executable, cli, "setup", "--yes", *_setup_args(args)])


def run_reinstall_command(args, deploy_base):
    """Purpose: `fabricctl reinstall` (manual 1.3.7.7, 1.3.7.13): a cold bundle of the whole install, sealed with a
             passphrase asked first, then fabric uninstalled and the bundle restored whole with any address changes,
             then setup run on it. Everything comes back: the CA, the directory, DNS with its TSIG keys, Keycloak, the
             vault and its key.
    Inputs:  args — --set key=value (host_ip, lan_cidr, lan_gateway), --key-stdin (the passphrase from standard
             input), --yes/-y, and setup's own options (passed on); or --from FILE (_reinstall_from); deploy_base —
             install root.
    Returns: 1 when refused or not confirmed (nothing touched); on success it does not return (setup replaces the
             process).
    Fails:   ValidationError is printed (exit 1): before anything is stopped for a change refused (linked sites, a
             new address this host does not have yet: setup would stop on it), a passphrase
             refused, the bundle not made; after the uninstall, the restore failing (the bundle is kept and named);
             OSError from os.execv.
    Feeds:   cli main (`reinstall`)."""
    ctx = SetupContext(deploy_base=deploy_base).load_state()
    v = ctx.vars
    if os.path.exists(ctx.vars_file) and "--from" in args:
        return _reinstall_from(args, ctx)
    try:
        if not os.path.exists(ctx.vars_file):
            raise ValidationError("fabric is not installed here: `sudo fabricctl setup` installs it")
        changes = read_changes(args)
        links = load_registry(os.path.join(ctx.config_dir, "federation.yaml"))
        changed = check_changes(changes, dict(v, linked=bool(links.get("upstream") or links.get("sites")),
                                              fabric_subnet=v.get("fabric_subnet") or "10.255.0.0/24",
                                              plan_subnets=kept_plan_subnets()))
        new = {k: (changed[k][1] if k in changed else v.get(k)) for k in NETWORK}
        problem = network_problem(new)
        if problem:
            raise ValidationError(f"{problem}. A reinstall runs setup at once, so this host needs its new address "
                                  "first; to move it to another VLAN or subnet, follow manual 4.2.4.8 (uninstall "
                                  "with a bundle, re-address the host, restore the bundle)")
        mac = address_in_use(str(new["host_ip"])) if "host_ip" in changed else ""
        if mac:
            raise ValidationError(f"another machine ({mac}) answers at {new['host_ip']} on this network: give this "
                                  "host an address no other machine uses (or stop the other machine) first")
        what = ", ".join(f"{k} {old} -> {new}" for k, (old, new) in changed.items()) or "no changes"
        print(f"Reinstall fabric ({what}): an encrypted backup bundle of all of it first, then fabric is removed and "
              "the bundle restored, then set up. Its passphrase opens the bundle if the reinstall stops part way.")
        key = read_backup_key([a for a in args if a == "--key-stdin"], v, opening=False)
        if "--yes" not in args and "-y" not in args:
            if ask("cli.reinstall.confirm", "Type 'yes' to continue: ").lower() != "yes":
                print("nothing changed")
                return 1
        source = stage_source(ctx)                       # uninstall deletes an installed copy
        cli = os.path.join(source, "lib", "fabriclib", "cli.py")
        bundle = make_backup(ctx.deploy_base, v, ctx.secrets_file, "reinstall", "cold", **key)
    except ValidationError as exc:
        print(f"error: {exc}\n{USAGE}", file=sys.stderr)
        return 1
    uninstall(ctx, host_account=False)                   # the restored directory still holds the host's account
    try:
        out = restore_bundle(ctx.deploy_base, bundle, {"passphrase": key["passphrase"]}, changes,
                       read_build(source)["version"])
    except ValidationError as exc:
        print(f"error: the restore did not finish: {exc}\nFabric is removed; its bundle is {bundle}: "
              f"`sudo fabricctl restore {bundle}` restores it.", file=sys.stderr)
        return 1
    for setting, value in out.get("leftover", []):
        print(f"  still at the old address: {setting} = {value}")
    os.execv(sys.executable, [sys.executable, cli, "setup", "--yes", *_setup_args(args)])
