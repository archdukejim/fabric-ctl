import json
import os

from fabriclib.common.console import BOLD, NC, ok
from fabriclib.common.sudo_owner import sudo_owner


def print_first_steps(ctx):
    """Purpose: what the admin does next, in order, as setup's last words (manual 3.3.2): first trust fabric's root
             names first (fabric's DNS, or a hosts-file line printed here), then the CA from http://<host_ip>/certs/
             over plain HTTP, checking its fingerprint, then (when the console asks for one)
             import the client certificate, then sign in. The order matters: a browser that does not trust the CA
             cannot reach the console safely (the owner nearly signed in first, 2026-10-09).
    Inputs:  ctx — SetupContext: vars install_webui, hostname_landing, hostname_mgr, webui_admin_user,
             webui_client_cert; the published ca-certs.json under <deploy_base>/nginx/www/certs; the login kit in the
             home of the account that ran sudo (sudo_owner).
    Returns: None; prints. Without the web UI: only the doctor line.
    Fails:   never for a missing ca-certs.json (the fingerprint is left out).
    Feeds:   setup/run_setup (after every step)."""
    v = ctx.vars
    if v.get("install_webui"):
        _, home, _, _ = sudo_owner()
        kit = os.path.join(home, "fabric-admin")
        user = v.get("webui_admin_user")
        try:
            sha256 = json.load(open(ctx.path("nginx", "www", "certs", "ca-certs.json")))["root-ca"]["sha256"]
        except (OSError, ValueError, KeyError):
            sha256 = ""
        ip = v.get("host_ip")
        names = " ".join(v.get(k) for k in ("hostname_landing", "hostname_mgr", "hostname_keycloak", "hostname_certs",
                                             "hostname_stepca", "hostname_openbao") if v.get(k))
        # the computer must find fabric's names before anything else: fabric's DNS, or its hosts file for a quick try
        steps = [f"{BOLD}FIRST point the computer you will manage fabric from at fabric for names{NC}: set its DNS "
                 f"server to {BOLD}{ip}{NC}\n       (its network settings, or your router's DHCP), or, to try it on "
                 f"one computer, add this line to its hosts file\n       (/etc/hosts; Windows: "
                 f"C:\\Windows\\System32\\drivers\\etc\\hosts):\n         {ip} {names}",
                 f"{BOLD}install fabric's root certificate{NC} on it: open {BOLD}http://{ip}/certs/{NC} (plain HTTP, "
                 f"no names needed; or http://{v.get('hostname_landing')}/),\n       download the root certificate"
                 + (f", check its SHA-256 fingerprint is\n         {sha256}\n       and" if sha256 else " and")
                 + f" install it as a trusted root (the same file: {kit}/root-ca.crt, .cer for Windows)"]
        if v.get("webui_client_cert"):
            steps.append(f"import your client certificate {kit}/{user}.p12 (its password: {kit}/p12-password.txt)")
        steps.append(f"{BOLD}then sign in{NC} at {BOLD}https://{v.get('hostname_mgr')}{NC} as {user}, with the "
                     "password you chose in setup")
        print("  Next:")
        for n, text in enumerate(steps, 1):
            print(f"    {n}. {text}")
        print(f"     Everything is in the login kit: {kit}/README.txt")
    ok("checks any time: sudo fabricctl doctor")
