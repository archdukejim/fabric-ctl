import glob
import os
import subprocess

from fabriclib.common.ask import ask
from fabriclib.setup.renew_service_certs import renew_service_certs

USAGE = """usage: fabricctl --service-cert                   their expiry dates, then asks to re-issue them all
       fabricctl --service-cert --apply           re-issue every service certificate without asking"""


def run_service_cert_command(ctx, args):
    """Purpose: `fabricctl --service-cert`: re-issue every core service certificate (which restarts the affected
             services). Without --apply it first lists the installed certificates' expiry dates and asks.
    Inputs:  ctx — SetupContext (loaded); args — the words after --service-cert (--apply).
    Returns: exit status: 0 (also when cancelled), 1 when fabric is not deployed.
    Fails:   SetupError from renew_service_certs; EOFError at the prompt without stdin.
    Feeds:   cli.py (--service-cert); the same issuing as `fabricctl certs --force`."""
    if not os.path.exists(ctx.vars_file):
        print(f"[✗] fabric not deployed ({ctx.vars_file} not found).")
        return 1
    if "--apply" not in args:
        print("[*] Current service certificates:\n")
        for cert in sorted(glob.glob(ctx.path("nginx", "certs", "*", "fullchain.pem"))):
            end = subprocess.run(["openssl", "x509", "-in", cert, "-noout", "-enddate"], capture_output=True,
                                 text=True).stdout.strip().partition("=")[2]
            print(f"  {os.path.basename(os.path.dirname(cert)):<30} expires {end or '?'}")
        print("\n[!] Re-issuing replaces every service certificate and restarts the affected services.")
        if ask("service_cert.confirm", "  Re-issue all service certificates? [y/N] ").lower() not in ("y", "yes"):
            print("[*] Cancelled.")
            return 0
    if renew_service_certs(ctx, force=True) != 0:
        print("[✗] Re-issuing failed: see the error above.")
        return 1
    print("[+] Service certificates re-issued (affected services reloaded or restarted).")
    return 0
