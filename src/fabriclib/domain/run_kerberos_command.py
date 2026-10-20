import getpass

from fabriclib.common.errors import ValidationError
from fabriclib.domain.list_spns import list_spns
from fabriclib.domain.read_options import read_options
from fabriclib.samba.kerberos_overview import kerberos_overview
from fabriclib.samba.set_kerberos_policy import set_kerberos_policy
from fabriclib.system.apply_changes import apply_changes

USAGE = """usage: fabricctl domain kerberos show                   the realm, its KDCs, the ticket policy, sign-in
       fabricctl domain kerberos spns                    every service principal and its account; duplicates flagged
       fabricctl domain kerberos policy [--ticket-hours N] [--renew-days N] [--skew-minutes N] [--no-apply]
  The ticket policy: a ticket of at least 1 hour and never longer than its renewal, a renewal of at most 30 days, a
  clock skew of 1 to 15 minutes (manual 1.6.12.9); applied at once unless --no-apply (the DC restarts)."""
OPTIONS = {"--ticket-hours": "ticket_hours", "--renew-days": "renew_days", "--skew-minutes": "skew_minutes"}


def run_kerberos_command(v, args):
    """Purpose: `fabricctl domain kerberos …` (manual 4.6.11): only parses and routes to the Kerberos functions, as
             root.
    Inputs:  v — rendered vars; args — list of str after `kerberos`.
    Returns: exit status: 0 done, 1 refused (with why) or a failed apply, 2 usage.
    Fails:   OSError from the vars file or the audit log (propagates).
    Feeds:   samba/run_domain_command."""
    try:
        if args == ["show"]:
            k = kerberos_overview(v)
            p = k["policy"]
            print(f"realm {k['realm']}; KDCs: {', '.join(k['kdcs']) if k['kdcs'] else k['kdcs_error']}")
            print(f"tickets {p['ticket_hours']} hours, renewable {p['renew_days']} days, clock skew "
                  f"{p['skew_minutes']} minutes; sign-in with the domain logon: "
                  f"{'on' if k['signin_kerberos'] else 'off'}")
            return 0
        if args == ["spns"]:
            got = list_spns(v)
            for r in got["spns"]:
                print(f"{r['spn']:<60} {r['account']:<24}" + ("  DUPLICATE" if r["duplicate"] else ""))
            if got["duplicates"]:
                print(f"duplicate SPNs (Kerberos breaks for both accounts): {', '.join(got['duplicates'])}")
            return 0
        if args[:1] == ["policy"]:
            o = read_options(args[1:], tuple(OPTIONS), ("--no-apply",))
            changes = {}
            for opt, key in OPTIONS.items():
                if opt in o:
                    if not o[opt].isdigit():
                        raise ValidationError(f"{opt} takes a whole number")
                    changes[key] = int(o[opt])
            if not changes:
                for key, value in kerberos_overview(v)["policy"].items():
                    print(f"{key}: {value}")
                return 0
            set_kerberos_policy(getpass.getuser(), changes, source="cli")
            if o.get("--no-apply"):
                print("recorded; apply with: sudo fabricctl --apply")
                return 0
            ok, output = apply_changes("root", "cli")
            print("applied (the DC's KDC uses the new policy)" if ok else output[-2000:])
            return 0 if ok else 1
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    print(USAGE)
    return 2
