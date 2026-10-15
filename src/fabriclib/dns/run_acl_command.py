import argparse
import sys

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.dns.add_acl_entries import add_acl_entries
from fabriclib.dns.builtin_acls import builtin_acls
from fabriclib.dns.remove_acl_entries import remove_acl_entries
from fabriclib.dns.set_acl_policy import set_acl_policy
from fabriclib.system.apply_changes import apply_changes

USAGE = """usage: fabricctl acl list                         every BIND ACL, its entries and its update policy
       fabricctl acl add <acl> <entry>...         create an ACL or add entries (IP, CIDR, 'key <tsig-key>', an ACL)
       fabricctl acl remove <acl> [<entry>...]    remove entries, or the whole ACL and its policy
       fabricctl acl policy <acl> --record HOST (repeatable) | --any-name [--types T,..] [--domain Z] | --clear
                                                  what the ACL's TSIG keys may update
  Every change is applied at once unless --no-apply."""


def _describe(policy):
    """Purpose: One line saying what the TSIG keys in an ACL may update under its policy.
    Inputs:  policy — a normalized ACL policy dict (domain, record_types, records or any_name).
    Returns: str "members may update <names> (<types>)".
    Fails:   KeyError if the policy lacks domain or record_types.
    Feeds:   run_acl_command (list, policy).
    """
    what = (", ".join(f"_acme-challenge.{r}.{policy['domain']}" for r in policy["records"])
            if policy.get("records") else f"any name in {policy['domain']}")
    return f"members may update {what} ({' '.join(policy['record_types'])})"


def run_acl_command(argv):
    """Purpose: `fabricctl acl list | add | remove | policy` — BIND ACLs (bind_acls) and their update policies; a change
             is applied right away unless --no-apply.
    Inputs:  argv — list of str after "acl". add/remove: acl and entries (IP, CIDR, 'key <tsig-key>', another ACL,
             any/none/localhost/localnets; `!` excludes). policy: acl, --record host (repeatable) or --any-name, --types
             (comma-separated, default TXT), --domain, or --clear. Reads vars.yaml.
    Returns: exit status: 0 on success; 1 on a ValidationError or OSError ("error: …" on stderr), including a failed
             apply (last 2000 characters of its output on stderr).
    Fails:   SystemExit 2 from argparse on bad arguments; "give --record host (repeatable) or --any-name" and callee
             ValidationErrors become exit 1; other exceptions (e.g. yaml.YAMLError, apply timeout) propagate.
    Feeds:   fabriclib/cli.py (`fabricctl acl`).
    Notes:   every ACL may query fabric's zones; a policy gives every TSIG key in the ACL update rights (e.g. DNS-01 TXT
             records for chosen hosts only).
    """
    ap = argparse.ArgumentParser(prog="fabricctl acl")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    add = sub.add_parser("add", help="create an ACL or add entries, then apply")
    add.add_argument("acl")
    add.add_argument("entries", nargs="+", help="e.g. 192.168.10.0/24 10.0.0.5 'key npm' '!10.0.0.9'")
    rm = sub.add_parser("remove", help="remove entries (or the whole ACL and its policy), then apply")
    rm.add_argument("acl")
    rm.add_argument("entries", nargs="*")
    pol = sub.add_parser("policy", help="set what the ACL's TSIG keys may update (created if missing)")
    pol.add_argument("acl")
    pol.add_argument("--record", action="append", default=[],
                     help="host whose DNS-01 challenge members may set (_acme-challenge.<host>.<zone>); repeatable")
    pol.add_argument("--any-name", action="store_true", help="members may update any name in the zone")
    pol.add_argument("--types", default="TXT", help="record types, comma-separated (default TXT)")
    pol.add_argument("--domain", help="zone (default: the fabric domain)")
    pol.add_argument("--clear", action="store_true", help="remove the policy (members lose these rights)")
    for p in (add, rm, pol):
        p.add_argument("--no-apply", action="store_true", help="only record the change; apply later")
    ap.usage = USAGE.removeprefix("usage: ")    # after the subparsers: they take their prog from it
    args = ap.parse_args(argv)

    try:
        if args.cmd == "list":
            data = load_vars()
            builtin = builtin_acls(data)
            policies = data.get("bind_acl_policies") or {}
            for name, entries in (data.get("bind_acls") or {}).items():
                tag = " (built in)" if name in builtin else ""
                print(f"{name}{tag}: {', '.join(entries or []) or '(empty)'}")
                if name in policies:
                    print(f"    policy: {_describe(policies[name])}")
            print("tsig-updaters (automatic): every TSIG key")
            return 0
        if args.cmd == "add":
            entries = add_acl_entries("root", args.acl, args.entries)
            print(f"{args.acl}: {', '.join(entries)}")
        elif args.cmd == "remove":
            remove_acl_entries("root", args.acl, args.entries)
            print(f"{args.acl}: " + ("removed" if not args.entries else "entries removed"))
        else:
            if args.clear:
                set_acl_policy("root", args.acl, None)
                print(f"{args.acl}: policy removed")
            else:
                if bool(args.record) == args.any_name:
                    raise ValidationError("give --record host (repeatable) or --any-name")
                policy = {"record_types": [t.strip() for t in args.types.split(",") if t.strip()]}
                if args.record:
                    policy["records"] = args.record
                else:
                    policy["any_name"] = True
                if args.domain:
                    policy["domain"] = args.domain
                print(f"{args.acl}: {_describe(set_acl_policy('root', args.acl, policy))}")
        if args.no_apply:
            print("not applied yet: sudo fabricctl --apply")
            return 0
        ok, output = apply_changes("root", "cli")
        if not ok:
            print(output[-2000:], file=sys.stderr)
            raise ValidationError("apply failed; BIND was not updated (see above)")
        print("applied")
        return 0
    except (ValidationError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
