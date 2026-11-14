import sys

from fabriclib.common.errors import ValidationError
from fabriclib.pki.list_issued import list_issued
from fabriclib.pki.publish_crl import REASONS
from fabriclib.pki.read_lifetimes import read_lifetimes
from fabriclib.pki.revoke_cert import revoke_cert
from fabriclib.pki.set_lifetimes import set_lifetimes
from fabriclib.setup.renew_service_certs import renew_service_certs

LIFETIME_FLAGS = {"--service-days": "service_days", "--renew-after-days": "renew_after_days",
                  "--acme-days": "acme_days", "--issue-default-days": "issue_default_days",
                  "--issue-max-days": "issue_max_days"}
USAGE = """usage: fabricctl certs [--force | --scheduled]        renew the service certificates that are due (2.1.5.4)
       fabricctl certs issued                       certificates issued by hand, client certificates and site CAs,
                                                    with their state (valid, expires soon, expired, revoked)
       fabricctl certs revoke <serial|name> [--reason R]
                                                    revoke one (published in the CRL at once, 2.1.5.10); R one of
                                                    """ + ", ".join(REASONS) + """
       fabricctl certs lifetimes [--service-days N] [--renew-after-days N] [--acme-days N]
                                 [--issue-default-days N] [--issue-max-days N]
                                                    show the certificate lifetimes and renewal, or set them: saved,
                                                    Step-CA converged, what is due renewed at once (2.1.5.14)"""


def _lifetimes(ctx, args):
    """Purpose: `fabricctl certs lifetimes [--<field> N ...]`: show the lifetimes, or set them (decision 2.1.5.14).
    Inputs:  ctx — SetupContext (not loaded); args — the arguments after "lifetimes".
    Returns: exit status: 0 shown or set, 2 usage (an unknown flag, a flag without its value).
    Fails:   ValidationError from set_lifetimes and read_lifetimes (printed by the caller, exit 1).
    Feeds:   run_certs_command."""
    given, rest = {}, list(args)
    while rest:
        flag = rest.pop(0)
        if flag not in LIFETIME_FLAGS or not rest or rest[0].startswith("--"):
            print(USAGE, file=sys.stderr)
            return 2
        given[LIFETIME_FLAGS[flag]] = rest.pop(0)
    if given:
        done = set_lifetimes("root", given, source="cli", ctx=ctx)
        for key, (old, new) in done["changed"].items():
            print(f"{key}: {old} -> {new}")
        print("Step-CA restarted with them; what is due was renewed" if done["changed"] else "nothing to change")
        for note in done["notes"]:
            print(f"note: {note}")
        return 0
    ctx.load_state()
    life = read_lifetimes(ctx.vars, ctx)
    values = life["values"]
    print(f"fabric's own certificates: {values['service_days']} days, renewed at {values['renew_after_days']} "
          f"days old")
    print(f"LAN machines over ACME:    {values['acme_days']} days (each machine's client renews; certbot: "
          f"{life['acme_client']['certbot']})")
    print(f"hand-issued:               {values['issue_default_days']} days by default, at most "
          f"{values['issue_max_days']}")
    left = life["intermediate_left_days"]
    print(f"no lifetime over:          {left} days (what the intermediate CA has left)" if left is not None
          else "no CA yet")
    for r in life["renewals"]:
        print(f"  {r['cn']:<40} renews {r['renews']} (expires {r['expires']})")
    for note in life["notes"]:
        print(f"note: {note}")
    return 0


def run_certs_command(ctx, argv):
    """Purpose: route `fabricctl certs …`: renewal, the issued list, revocation, the lifetimes (2.1.5.14).
    Inputs:  ctx — SetupContext (not loaded); argv — list of str after "certs" (--deploy-base and its value removed).
    Returns: exit status: 0 done, 1 a failure (renewal) or a refusal (ValidationError printed), 2 usage.
    Fails:   never raises a ValidationError (printed, exit 1); OSError and subprocess errors propagate.
    Feeds:   cli main (`certs`)."""
    flags = [a for a in argv if a.startswith("--")]
    try:
        if argv[:1] == ["issued"] and len(argv) == 1:
            rows = list_issued(limit=1000)
            for r in rows:
                print(f"{r.get('serial', '?'):<42} {r['status']:<13} {r.get('not_after', ''):<26} "
                      f"{r.get('kind', ''):<8} {r.get('subject', '')}")
            print(f"{len(rows)} certificate(s)" if rows else "nothing issued by hand yet")
            return 0
        if argv[:1] == ["lifetimes"]:
            return _lifetimes(ctx, argv[1:])
        if argv[:1] == ["revoke"]:
            rest = list(argv[1:])
            reason = "unspecified"
            if "--reason" in rest:
                i = rest.index("--reason")
                if i + 1 >= len(rest):
                    print(USAGE, file=sys.stderr)
                    return 2
                reason = rest.pop(i + 1)
                rest.pop(i)
            if len(rest) != 1 or rest[0].startswith("--"):
                print(USAGE, file=sys.stderr)
                return 2
            done = revoke_cert(ctx.load_state().vars, "root", rest[0], reason, source="cli")
            print(f"revoked {done['subject']} (serial {done['serial']}, {done['reason']}): in the CRL now")
            return 0
        if argv and not argv[0].startswith("--") or set(flags) - {"--force", "--scheduled"} \
                or {"--force", "--scheduled"} <= set(flags):
            print(USAGE, file=sys.stderr)
            return 2
        return renew_service_certs(ctx, force="--force" in flags, scheduled="--scheduled" in flags)
    except ValidationError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
