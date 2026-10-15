import argparse
import sys

from fabriclib.common.ask import ask_secret
from fabriclib.common.errors import ValidationError
from fabriclib.dns.add_tsig_key import add_tsig_key
from fabriclib.dns.list_tsig_keys import list_tsig_keys
from fabriclib.dns.remove_tsig_key import remove_tsig_key
from fabriclib.dns.replace_tsig_secret import replace_tsig_secret
from fabriclib.dns.set_key_acls import set_key_acls
from fabriclib.dns.update_tsig_key import update_tsig_key
from fabriclib.system.apply_changes import apply_changes

USAGE = """usage: fabricctl tsig list                        every TSIG key: algorithm, types, what it may update, ACLs
       fabricctl tsig add <name> [scope] [--secret-file F | --secret-prompt]
                                                  add a key (a new secret, or an existing one you give)
       fabricctl tsig update <name> [scope] [--drop-acl A]
                                                  change what a key may update (secret untouched)
       fabricctl tsig set-secret <name> --secret-file F | --secret-prompt
                                                  replace a key's secret with one you give
       fabricctl tsig rotate <name>               give a key a newly generated secret
       fabricctl tsig remove <name>               remove a key
  scope: --domain Z --record HOST (repeatable) | --any-name, --types T,.. --algorithm A --out FILE --acl A
  (repeatable). Every change is applied at once unless --no-apply. A secret never goes on the command line."""


def _secret(args):
    """Purpose: Read an existing TSIG secret without putting it on the command line.
    Inputs:  args — argparse namespace; uses secret_file (path) or secret_prompt (bool) when present.
    Returns: the stripped secret (str) from the file or a hidden prompt; None when neither is given.
    Fails:   OSError if the file cannot be read (caught by run_tsig_command); EOFError/KeyboardInterrupt from getpass
             propagate.
    Feeds:   run_tsig_command (add, set-secret).
    """
    if getattr(args, "secret_file", None):
        with open(args.secret_file) as f:
            return f.read().strip()
    if getattr(args, "secret_prompt", False):
        return ask_secret("tsig.secret", "TSIG secret (base64): ").strip()
    return None


def _stored_key(name):
    """Purpose: A TSIG key's entry as stored in vars.yaml.
    Inputs:  name — str key name.
    Returns: the tsig_keys dict, or None if there is no such key.
    Fails:   OSError or yaml.YAMLError from load_vars.
    Feeds:   run_tsig_command (update with only --acl / --drop-acl).
    """
    from fabriclib.common.load_vars import load_vars
    return next((k for k in load_vars().get("tsig_keys") or [] if k.get("name") == name), None)


def _ini(key):
    """Purpose: The rfc2136.ini path to print for a key when list_tsig_keys does not list it.
    Inputs:  key — dict with name and optional out.
    Returns: the key's out, else "/opt/<name>/rfc2136.ini".
    Fails:   KeyError if key has no name.
    Feeds:   run_tsig_command (after-apply message).
    Notes:   hard-codes /opt, while apply writes the file under the deploy base (deploy/install_runtime_dirs).
    """
    return key.get("out") or f"/opt/{key['name']}/rfc2136.ini"


def run_tsig_command(argv):
    """Purpose: `fabricctl tsig list | add | update | set-secret | rotate | remove` — TSIG keys for RFC2136 dynamic
             updates (e.g. certbot's rfc2136 plugin in nginx-proxy-manager); a change is applied right away unless
             --no-apply.
    Inputs:  argv — list of str after "tsig". add/update: name, --domain, --record (repeatable), --any-name, --types,
             --algorithm, --out, --acl (repeatable); update also --drop-acl; add and set-secret: --secret-file or
             --secret-prompt. Reads vars.yaml.
    Returns: exit status: 0 on success; 1 on a ValidationError or OSError ("error: …" on stderr), including a failed
             apply.
    Fails:   SystemExit 2 from argparse on bad arguments; "--record and --any-name exclude each other", "nothing to
             change …", "no TSIG key named …", "give the secret with --secret-prompt or --secret-file" and callee
             ValidationErrors become exit 1; other exceptions propagate.
    Feeds:   fabriclib/cli.py (`fabricctl tsig`).
    Notes:   secrets never appear in argv (world-readable): an existing secret comes from a file or a hidden prompt.
    """
    ap = argparse.ArgumentParser(prog="fabricctl tsig")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")

    def scope(p):
        p.add_argument("name")
        p.add_argument("--domain", help="zone (default: the fabric domain)")
        p.add_argument("--record", action="append", default=None,
                       help="host allowed a DNS-01 challenge (_acme-challenge.<host>.<zone>); repeatable")
        p.add_argument("--any-name", action="store_true",
                       help="may update any name in the zone (explicit; otherwise only --record hosts or ACL policies)")
        p.add_argument("--types", help="record types it may change, comma-separated (default TXT)")
        p.add_argument("--algorithm", help="default hmac-sha256")
        p.add_argument("--out", help="where to write its rfc2136.ini (default /opt/<name>/rfc2136.ini)")
        p.add_argument("--acl", action="append", default=[],
                       help="put the key in this BIND ACL (created if missing); repeatable")

    def secret_opts(p):
        g = p.add_mutually_exclusive_group()
        g.add_argument("--secret-file", help="file holding an existing base64 secret")
        g.add_argument("--secret-prompt", action="store_true", help="type/paste an existing secret (hidden)")

    add = sub.add_parser("add", help="add a key (new secret, or keep an existing one)")
    scope(add)
    secret_opts(add)
    upd = sub.add_parser("update", help="change what a key may update (secret untouched)")
    scope(upd)
    upd.add_argument("--drop-acl", action="append", default=[], help="take the key out of this ACL; repeatable")
    setp = sub.add_parser("set-secret", help="replace a key's secret with one you give")
    setp.add_argument("name")
    secret_opts(setp)
    rot = sub.add_parser("rotate", help="give a key a newly generated secret")
    rot.add_argument("name")
    rm = sub.add_parser("remove", help="remove a key")
    rm.add_argument("name")
    for p in (add, upd, setp, rot, rm):
        p.add_argument("--no-apply", action="store_true", help="only record the change; apply later")
    ap.usage = USAGE.removeprefix("usage: ")    # after the subparsers: they take their prog from it
    args = ap.parse_args(argv)

    try:
        if args.cmd == "list":
            keys = list_tsig_keys()
            for k in keys:
                print(f"{k['name']:<24} {k['algorithm']:<12} {k['types']:<8} {k['scope']}\n"
                      f"{'':<24} ACLs: {', '.join(k['acls']) or '-'}   credentials: {k['ini']}")
            if not keys:
                print("no TSIG keys")
            return 0

        if args.cmd == "add":
            secret = _secret(args)
            entry = {"name": args.name}
            for field, val in (("domain", args.domain), ("records", args.record), ("algorithm", args.algorithm),
                               ("out", args.out)):
                if val:
                    entry[field] = val
            if args.types:
                entry["record_types"] = [t.strip() for t in args.types.split(",") if t.strip()]
            if args.any_name:
                if args.record:
                    raise ValidationError("--record and --any-name exclude each other")
                entry["any_name"] = True
            key, _ = add_tsig_key("root", entry, secret)
            acls = set_key_acls("root", key["name"], add=args.acl) if args.acl else []
            msg = (f"TSIG key '{key['name']}' added ({'existing secret kept' if secret else 'new secret'})"
                   + (f", in ACL {', '.join(acls)}." if acls else "."))
        elif args.cmd == "update":
            changes = {}
            if args.any_name and args.record:
                raise ValidationError("--record and --any-name exclude each other")
            if args.any_name:
                changes.update(records=[], any_name=True)
            elif args.record:
                changes.update(records=args.record, any_name=None)
            if args.types:
                changes["record_types"] = [t.strip() for t in args.types.split(",") if t.strip()]
            for field in ("domain", "algorithm", "out"):
                if getattr(args, field):
                    changes[field] = getattr(args, field)
            if not changes and not args.acl and not args.drop_acl:
                raise ValidationError("nothing to change (--record, --any-name, --types, --domain, --algorithm, "
                                      "--out, --acl, --drop-acl)")
            key = update_tsig_key("root", args.name, changes) if changes else _stored_key(args.name)
            if key is None:
                raise ValidationError(f"no TSIG key named {args.name!r}")
            acls = set_key_acls("root", args.name, add=args.acl, drop=args.drop_acl)
            scope = next(k["scope"] for k in list_tsig_keys() if k["name"] == args.name)
            msg = f"TSIG key '{args.name}' (ACLs: {', '.join(acls) or '-'}) may update: {scope}."
        elif args.cmd in ("set-secret", "rotate"):
            given = _secret(args) if args.cmd == "set-secret" else None
            if args.cmd == "set-secret" and not given:
                raise ValidationError("give the secret with --secret-prompt or --secret-file")
            replace_tsig_secret("root", args.name, given)
            key = {"name": args.name}
            msg = (f"TSIG key '{args.name}': secret replaced." if given else
                   f"TSIG key '{args.name}': new secret generated; update its clients.")
        else:
            remove_tsig_key("root", args.name)
            key, msg = None, f"TSIG key '{args.name}' removed."

        print(msg)
        if args.no_apply:
            print("not applied yet: sudo fabricctl --apply")
            return 0
        ok, output = apply_changes("root", "cli")
        if not ok:
            print(output[-2000:], file=sys.stderr)
            raise ValidationError("apply failed; BIND was not updated (see above)")
        if key:
            ini = next((k["ini"] for k in list_tsig_keys() if k["name"] == key["name"]), _ini(key))
            print(f"applied. RFC2136 client settings (server, port, key, secret, algorithm): {ini} (0600)")
        else:
            print("applied.")
        return 0
    except (ValidationError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
