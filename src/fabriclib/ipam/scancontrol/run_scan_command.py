import sys
import time

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.scancontrol.limits import WAIT
from fabriclib.ipam.scancontrol.list_scan_requests import list_scan_requests
from fabriclib.ipam.scancontrol.request_scan import request_scan
from fabriclib.ipam.scancontrol.show_scan_requests import show_scan_requests

USAGE = """usage: fabricctl ipam scan <subnet> --site S [--no-wait]   a scan at another site: requested, then awaited
       fabricctl ipam scan-requests [--site S]           S's (this site's) scan requests and their answers"""
FLAGS = ("--site",)
BARE = ("--no-wait",)


def _parse(args):
    """Purpose: split the arguments into positionals, --site's value and the bare flags.
    Inputs:  args — list of str.
    Returns: (positionals, {flag: value}, set of bare flags).
    Fails:   ValidationError: a flag without a value, a flag the command does not know.
    Feeds:   run_scan_command."""
    pos, vals, bare, i = [], {}, set(), 0
    while i < len(args):
        a = args[i]
        if a in FLAGS:
            if i + 1 >= len(args):
                raise ValidationError(f"{a} needs a value")
            vals[a] = args[i + 1]
            i += 2
            continue
        if a in BARE:
            bare.add(a)
        elif a.startswith("--"):
            raise ValidationError(f"unknown option {a}")
        else:
            pos.append(a)
        i += 1
    return pos, vals, bare


def _wait(v, req, secrets, container, sleep, clock):
    """Purpose: wait for a request's answer, reading the serving site's requests every 5 s for up to WAIT seconds.
    Inputs:  v — fabric vars; req — request_scan's result; secrets, container — as list_scan_requests; sleep, clock —
             time.sleep and time.monotonic (tests give their own).
    Returns: the answered row, or None when it is still pending.
    Fails:   ValidationError from the reads.
    Feeds:   run_scan_command."""
    end = clock() + WAIT
    while clock() < end:
        sleep(5)
        row = next((r for r in list_scan_requests(v, req["site"], secrets, container) if r["id"] == req["id"]), None)
        if row is not None and row["state"] != "pending":
            return row
    return None


def run_scan_command(v, cmd, args, secrets=None, container="samba", sleep=time.sleep, clock=time.monotonic):
    """Purpose: `fabricctl ipam scan <subnet> --site S` and `scan-requests` (manual 1.10.4.36; Volume 4: 4.10.2.15):
             a scan at another site, and the requests' answers. Routes only: the rules are in request_scan and
             list_scan_requests. Run as root, acting for the Enterprise Admin.
    Inputs:  v — the rendered vars; cmd — "scan" or "scan-requests"; args — the arguments after it; secrets — fabric's
             secrets (default loaded by the functions); container — the DC's container; sleep, clock — for scan's
             wait (tests give their own). See USAGE.
    Returns: exit status: 0 success (and help; a request still pending when the wait ends); 1 a refusal (printed
             with why), or an answer that is not "done"; 2 usage (printed to stderr).
    Fails:   ValidationError is caught (exit 1); other exceptions propagate.
    Feeds:   ipam/run_ipam_command (`fabricctl ipam scan … --site`, `scan-requests`)."""
    if args[:1] in (["--help"], ["-h"], ["help"]):
        print(USAGE)
        return 0
    try:
        pos, vals, bare = _parse(args)
        site = vals.get("--site", "")
        if cmd == "scan" and len(pos) == 1 and site:
            req = request_scan(v, "root", site, pos[0], secrets, container)
            print(f"scan of {req['cidr']} ({req['subnet']}) requested at {req['site']}: {req['id']}; {req['site']}'s "
                  "plan poll runs it within about 30 s")
            if "--no-wait" in bare:
                return 0
            row = _wait(v, req, secrets, container, sleep, clock)
            if row is None:
                print(f"still pending after {WAIT} s: fabricctl ipam scan-requests --site {req['site']} shows it "
                      "when it is answered")
                return 0
            print(show_scan_requests(req["site"], [row]), end="")
            return 0 if row["state"] == "done" else 1
        if cmd == "scan-requests" and not pos and not bare:
            rows = list_scan_requests(v, site, secrets, container)
            print(show_scan_requests(site or v["site_name"], rows), end="")
            return 0
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(USAGE, file=sys.stderr)
    return 2
