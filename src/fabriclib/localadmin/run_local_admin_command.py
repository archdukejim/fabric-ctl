import getpass
import os

from fabriclib.common.errors import ValidationError
from fabriclib.localadmin.check_local_admin import check_local_admin
from fabriclib.localadmin.checkout_local_admin import checkout_local_admin
from fabriclib.localadmin.local_admin_status import local_admin_status
from fabriclib.localadmin.set_local_admin_policy import set_local_admin_policy
from fabriclib.localadmin.set_local_admin_ssh import set_local_admin_ssh

USAGE = """usage: sudo fabricctl local-admin status                this host's local-admin: policy, password set on,
                                                       a use or check-out seen, rotation due, SSH (never a password)
       sudo fabricctl local-admin checkout --reason "<why>"  its password, shown once (audited; rotated after use)
       sudo fabricctl local-admin policy after-use|keep-until-checkout   its rotation policy (audited)
       sudo fabricctl local-admin ssh on|off [--dc dc-NNNN]   local-admin over SSH for a DC's host (the domain's
                                                       switch, audited; default this host's DC; off by default)
       sudo fabricctl local-admin check [--scheduled]   the hourly run now: a use seen, a rotation due, SSH applied
  As root only, acting for the Enterprise Admin (manual 4.7.1.3)."""


def _print_status(s):
    """Purpose: the status, one fact a line.
    Inputs:  s — local_admin_status's result.
    Returns: None.
    Fails:   never.
    Feeds:   run_local_admin_command."""
    if not s["made"]:
        print("local-admin: not made by fabric on this host (the `local_admin` host change: sudo fabricctl setup "
              "--step localadmin)")
        return
    print(f"local-admin: {'the account exists' if s['account'] else 'MISSING on this host'}; policy {s['policy']}")
    print(f"  password: OpenBao's version {s['version']}, set {s['set_at']} ({s['reason']})")
    if s["used"]:
        print(f"  used: {s['used']['when']} ({s['used']['how']})")
    if s["checkout"]:
        c = s["checkout"]
        print(f"  checked out: {c['when']} by {c['by']} ({c['source']}): {c['reason']}")
    if s["due"]:
        print(f"  a new password is due {s['due']} ({s['due_why']})")
    if s["waiting"]:
        print(f"  WAITING since {s['waiting']['since']}: {s['waiting']['why']} (the used password stays valid)")
    d = s["domain_ssh"]
    print("  SSH in the domain: " + (f"could not be read ({d['error']})" if "error" in d else
                                     ("ON" if d["ssh"] else "off") + (f", set by {d['by']} {d['when']}"
                                                                       if d.get("by") else " (never set)")))
    a = s["ssh"] or {}
    print(f"  SSH applied here: {'ON (a relaxation)' if a.get('on') else 'off'}"
          + (f", at {a.get('applied_at')}" if a.get("applied_at") else ""))
    last = s["last_check"]
    if last:
        print(f"  last check: {last['when']}, {'ok' if last['ok'] else 'FAILED'}")


def run_local_admin_command(v, config_dir, args):
    """Purpose: `fabricctl local-admin …` (manual 4.7.1.3; decisions 2.1.7.16 to 2.1.7.20): only parses and routes to
             the status, the check-out, the policy, the SSH switch and the hourly check.
    Inputs:  v — rendered vars; config_dir — the install's config folder; args — list of str after `local-admin`.
    Returns: exit status: 0 done, 1 refused or failed (said why), 2 usage.
    Fails:   OSError, ValueError from the record (propagate).
    Feeds:   cli.main (which refuses anyone but root first)."""
    actor = os.environ.get("SUDO_USER") or getpass.getuser()
    try:
        if args == ["status"]:
            _print_status(local_admin_status(v, config_dir))
            return 0
        if len(args) == 3 and args[0] == "checkout" and args[1] == "--reason":
            out = checkout_local_admin(v, config_dir, None, actor, args[2])
            print(f"local-admin's password (OpenBao's version {out['version']}), shown once:")
            print(f"password:  {out['password']}")
            print(f"It is rotated after use: by {out['rotates_after']} (UTC) at the latest. Checked out, audited.")
            return 0
        if len(args) == 2 and args[0] == "policy":
            out = set_local_admin_policy(v, config_dir, args[1], actor)
            print(f"local-admin's policy: {out['policy']}" + ("" if out["changed"] else " (already)"))
            return 0
        if args[:1] == ["ssh"] and len(args) in (2, 4) and (len(args) == 2 or args[2] == "--dc"):
            out = set_local_admin_ssh(v, config_dir, None, actor, args[1], args[3] if len(args) == 4 else None)
            print(f"local-admin over SSH for {out['dc']}'s host: {'ON (a relaxation)' if out['ssh'] else 'off'}"
                  + ("" if out["changed"] else " (already)"))
            for line in out["applied"]:
                print(f"  {line}")
            return 0
        if args in (["check"], ["check", "--scheduled"]):
            out = check_local_admin(v, config_dir, actor, "timer" if "--scheduled" in args else "cli")
            for line in out["lines"]:
                print(line)
            return 0 if out["ok"] else 1
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    print(USAGE)
    return 2
