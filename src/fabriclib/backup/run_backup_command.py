import getpass
import sys

from fabriclib.backup.check_bundle import check_bundle
from fabriclib.backup.list_bundles import list_bundles
from fabriclib.backup.make_backup import make_backup
from fabriclib.backup.prune_bundles import prune_bundles
from fabriclib.backup.read_backup_key import read_backup_key
from fabriclib.backup.set_backup_schedule import set_backup_schedule
from fabriclib.common.errors import ValidationError

USAGE = """usage: fabricctl backup [--public-key age1… | --scheduled-key | --key-stdin]   a bundle of everything, now
       fabricctl backup list                    the bundles in /var/backups/fabric
       fabricctl backup check <file>            whether a bundle is whole (no key needed)
       fabricctl backup schedule [--time HH:MM] [--keep N] [--public-key age1…] | --off
  A bundle made by hand asks a passphrase twice; one made to a public key opens only with its private key, which
  stays off this host. Restore: `fabricctl restore <file>` (manual 1.3.7)."""


def _flag(args, name, cast=str):
    """Purpose: a flag's value.
    Inputs:  args — the arguments; name — the flag; cast — str or int.
    Returns: the value cast, or None when the flag is not given.
    Fails:   ValidationError for a missing or bad value.
    Feeds:   run_backup_command."""
    if name not in args:
        return None
    i = args.index(name)
    try:
        return cast(args[i + 1])
    except (IndexError, ValueError):
        raise ValidationError(f"{name} needs a value") from None


def run_backup_command(base, v, secrets_file, args):
    """Purpose: `fabricctl backup …` (manual 1.3.7.11): routes to make_backup, list_bundles, check_bundle and
             set_backup_schedule, and prints. `--scheduled` is the timer's own run: the schedule's key, kind
             scheduled, then the oldest scheduled bundles beyond backup_keep removed.
    Inputs:  base — install root; v — vars.yaml dict; secrets_file — fabric-secrets.yml's path; args — after `backup`.
    Returns: exit status: 0 done, 1 refused (the reason printed), 2 usage.
    Fails:   never raises ValidationError (printed); OSError propagates.
    Feeds:   cli.main."""
    op = args[0] if args and not args[0].startswith("-") else ""
    actor = getpass.getuser()
    try:
        if op == "":
            key = read_backup_key(args, v, opening=False)
            kind = "scheduled" if "--scheduled" in args else "manual"
            make_backup(base, v, secrets_file, kind, "online", actor=actor, **key)
            if kind == "scheduled":
                for name in prune_bundles(int(v.get("backup_keep") or 7)):
                    print(f"removed the older scheduled bundle {name}")
        elif op == "list":
            rows = list_bundles()
            for r in rows:
                state = f"unreadable: {r['error']}" if r["error"] else ", ".join(r["sections"]) or "empty"
                print(f"{r['file']}  {r['size'] // 2**20} MiB  fabric {r['fabric_version'] or '?'}  {state}")
            if not rows:
                print("no bundles in /var/backups/fabric")
        elif op == "check" and len(args) == 2:
            m = check_bundle(args[1])
            print(f"whole: {args[1]} — {m['host']}, {m['made']}, fabric {m.get('fabric_version')}, {m['kind']} "
                  f"({m['method']}), opened by {'a passphrase' if m['opened_by'] == 'passphrase' else m['opened_by']}")
        elif op == "schedule":
            out = set_backup_schedule(actor, time=_flag(args, "--time"), keep=_flag(args, "--keep", int),
                                      public_key=_flag(args, "--public-key"), off="--off" in args)
            print(f"backup schedule: {out['schedule']}, keeping {out['keep']} scheduled bundles"
                  + (f", to {out['public_key']}" if out["public_key"] else ""))
        else:
            print(USAGE)
            return 2
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0
