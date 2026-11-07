#!/usr/bin/env python3
"""A real site to look at (global Rule 9: a UI change is checked in the running app), going through each page at the
pace of whoever drives it: real listener, real TLS, real pages; Guided's questions stood in for by a short list, and a
short log for the install. Prints the URL and the code. Dev only: never shipped, and it binds what it is told.

    python3 tests/setup/site/preview.py [first port]
"""
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from support import listener_lib  # noqa: E402

import fabriclib.setup.detach.follow_run as fr  # noqa: E402
import fabriclib.setup.site.finish_data as fd  # noqa: E402
import fabriclib.setup.site.guided_site as gs  # noqa: E402
from fabriclib.common.ask import ask, ask_secret  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.detach.constants import LOG  # noqa: E402
from fabriclib.setup.detach.write_run import write_run  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402

gs.detect_network = lambda: {"hostname": "fabric-preview", "host_ip": "127.0.0.1", "lan_cidr": "127.0.0.0/8"}
gs.open_site_port = lambda port, cidr: False


def no_mint(ctx, addresses, name):
    """The preview has no CA: the finish on the temporary certificate, saying so."""
    raise SetupError("this is a preview")


def main():
    first = int(sys.argv[1]) if len(sys.argv) > 1 else 28600
    lib, user = listener_lib()
    fd.mint_site_cert = no_mint
    with tempfile.TemporaryDirectory() as base:
        ctx = SetupContext(deploy_base=base)
        site = gs.GuidedSite(ctx, first=first, last=first + 10, record=os.path.join(base, "site-port"), lib_dir=lib, user=user, after=3600)
        try:
            site.open()
            print("\n  A few details about this network:")
            answer = ask("preview.domain", "  DNS domain (e.g. home.arpa) ⚠ Permanent [home.arpa]: ", "home.arpa")
            while "." not in answer:
                print("    not a valid domain")
                answer = ask("preview.domain", "  DNS domain (e.g. home.arpa) ⚠ Permanent [home.arpa]: ", "home.arpa")
            ask("preview.host", "  This host's name [fabric]: ", "fabric")
            ask_secret("preview.password", "    Password for pat (web console sign-in, not shown): ")
            print("\nfabricctl setup will:\n  ✓ Host firewall: only fabric's ports inbound, from the LAN only\n"
                  "  ✓ Create an internal CA\n  · Optional, off: DHCP with Kea\n\n"
                  "Changes to this host outside fabric's own folders — [P]roceed allows all of these\n"
                  "  Packages (required)\n    - apt: docker.io, docker-compose-v2\n  Firewall (recommended)\n"
                  "    - ufw: deny incoming and allow outgoing by default, then enable ufw")
            if ask("setup.plan", "[P]roceed (allows the host changes listed), [M]enu, or [Q]uit? ").lower() != "p":
                return 0
            site.proceeding()
            os.makedirs(ctx.path("nginx", "www", "certs"))
            os.makedirs(ctx.config_dir, exist_ok=True)
            with open(ctx.vars_file, "w") as f:
                f.write("host_ip: 127.0.0.1\ndomain: home.arpa\nhostname_mgr: fabric-ctl.home.arpa\n")
            with open(ctx.path("nginx", "www", "certs", "root-ca.crt"), "w") as f:
                f.write(site.cert)
            log = os.path.join(ctx.config_dir, LOG)
            running = [True]
            pid = os.fork()
            if pid == 0:
                with open(log, "a") as f:
                    for n in range(40):
                        f.write(f"  ✓ step {n} of the install\n")
                        f.flush()
                        time.sleep(0.25)
                write_run(ctx.config_dir, {"id": "p", "state": "done", "result": 0, "done": []})
                os._exit(0)
            open(log, "a").close()

            def alive():
                running[0] = os.waitpid(pid, os.WNOHANG) == (0, 0) if running[0] else False
                return running[0]
            saved = gs.follow_run
            gs.follow_run = lambda config_dir, out=None: saved(config_dir, running=alive, out=out, sleep=time.sleep, interval=0.1)
            fr.ENDED_GAP = 0.1
            return site.follow(ctx.config_dir)
        except KeyboardInterrupt:
            return 130
        finally:
            site.close()


if __name__ == "__main__":
    sys.exit(main())
