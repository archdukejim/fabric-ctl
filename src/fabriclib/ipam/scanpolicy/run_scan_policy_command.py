import sys

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.scanpolicy.read_scan_policy import read_scan_policy
from fabriclib.ipam.scanpolicy.set_scan_policy import set_scan_policy
from fabriclib.ipam.scanpolicy.show_scan_policy import show_scan_policy

USAGE = """usage: fabricctl ipam scan-policy [show] [--site S]      whether scans may run here (or at S), and why
       fabricctl ipam scan-policy set org allow|deny [--enforced on|off]
                                                     the organisation's level (enforced: it wins at every site)
       fabricctl ipam scan-policy set site allow|deny|inherit [--site S]
                                                     a site's level (inherit: the organisation's decides)"""
FLAGS = ("--site", "--enforced")


def _parse(args):
    """Purpose: split the arguments into positionals and --site / --enforced values.
    Inputs:  args — list of str.
    Returns: (positionals, {flag: value}).
    Fails:   ValidationError: a flag without a value, a flag the command does not know.
    Feeds:   run_scan_policy_command."""
    pos, vals, i = [], {}, 0
    while i < len(args):
        a = args[i]
        if a in FLAGS:
            if i + 1 >= len(args):
                raise ValidationError(f"{a} needs a value")
            vals[a] = args[i + 1]
            i += 2
            continue
        if a.startswith("--"):
            raise ValidationError(f"unknown option {a}")
        pos.append(a)
        i += 1
    return pos, vals


def run_scan_policy_command(v, args, secrets=None, container="samba"):
    """Purpose: `fabricctl ipam scan-policy …` (manual 1.10.4.27.5; Volume 4: 4.10.2.18): the scan policy shown, or one
             of its levels set. Routes only: the rules are in read_scan_policy and set_scan_policy.
    Inputs:  v — the rendered vars; args — the arguments after "scan-policy"; secrets — fabric's secrets (default loaded
             by the functions); container — the DC's container. See USAGE.
    Returns: exit status: 0 success (and help); 1 a refusal (printed with why); 2 usage (printed to stderr).
    Fails:   ValidationError is caught (exit 1); other exceptions propagate.
    Feeds:   ipam/run_ipam_command (`fabricctl ipam scan-policy`)."""
    if args[:1] in (["--help"], ["-h"], ["help"]):
        print(USAGE)
        return 0
    try:
        pos, vals = _parse(args)
        site = vals.get("--site", "")
        if pos in ([], ["show"]) and "--enforced" not in vals:
            print(show_scan_policy(read_scan_policy(v, site, secrets, container)), end="")
            return 0
        if len(pos) == 3 and pos[0] == "set":
            enforced = None
            if "--enforced" in vals:
                if vals["--enforced"].lower() not in ("on", "off"):
                    raise ValidationError("--enforced is on or off")
                enforced = vals["--enforced"].lower() == "on"
            out = set_scan_policy(v, "root", pos[1], pos[2], enforced, site, secrets, container)
            r = out["result"]
            print(("the organisation's scan policy" if r["level"] == "org" else f"{r['site']}'s scan policy")
                  + f" is {r['policy']}" + ((", enforced" if r["enforced"] else ", not enforced")
                                            if r["level"] == "org" and r["enforced"] is not None else "")
                  + ": the next scan reads it")
            print(show_scan_policy(read_scan_policy(v, "" if r["level"] == "org" else r["site"], secrets, container)),
                  end="")
            return 0
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(USAGE, file=sys.stderr)
    return 2
