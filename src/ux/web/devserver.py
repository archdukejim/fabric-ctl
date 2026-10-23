#!/usr/bin/env python3
"""Fabric web UI — DEV PREVIEW. The real pages (src/webui/views) with sample data:
no sign-in, no client certificate, no fabric-agent, nothing saved or
applied. Record edits live in memory until the process stops. The preview
itself is src/webui/devpreview/.

A separate entry point on purpose: the production server (server.py) has no
dev switch, so this can never be turned on in a real install.

  python3 src/ux/web/devserver.py                                 # from a checkout: http://127.0.0.1:8080
  docker run --rm -p 127.0.0.1:8080:8080 --entrypoint /usr/bin/python3 \\
      fabric/web:local /app/webui/devserver.py --bind 0.0.0.0   # from the image
"""
import argparse
import os
import sys
from http.server import ThreadingHTTPServer

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# the folder holding the webui package: lib/ on a host (lib/webui/devserver.py); src/ in a checkout
# (src/ux/web/devserver.py), which also holds fabriclib, so the preview uses fabric's real rules
for _p in (os.path.dirname(_PARENT), _PARENT):
    if os.path.isdir(os.path.join(_p, "webui")):
        sys.path.insert(0, _p)
from webui.devpreview.dev_handler import DevHandler  # noqa: E402
from webui.devpreview.fabric_rules import BUNDLES  # noqa: E402
from webui.devpreview.fake_connection import FakeConnection  # noqa: E402


def main():
    """Purpose: Start the dev preview HTTP server (sample data, no sign-in, nothing saved).
    Inputs:  command line: --bind (default 127.0.0.1), --port (default 8080), --as <bundle> to see the UI with that
             role bundle's permissions (default admin: every permission; none: no fabric role, My account only).
    Returns: never returns normally (serve_forever).
    Fails:   SystemExit via argparse for bad arguments or an unknown bundle (every non-admin bundle when fabriclib is
             missing, as BUNDLES is then empty); OSError if the address is in use.
    Feeds:   `python3 src/ux/web/devserver.py`; tests/webui/test_devserver.py starts it as a subprocess.
    """
    ap = argparse.ArgumentParser(description="Fabric web UI dev preview (sample data, no sign-in, no backend)")
    ap.add_argument("--bind", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--as", dest="bundle", default="admin",
                    help="see the UI as this role bundle: " + ", ".join(sorted(BUNDLES)) + ", or none (a person of "
                         "the domain with no fabric role, who sees My account only); default admin")
    args = ap.parse_args()
    if args.bundle == "none":                       # no fabric role: My account only (2.1.8.11)
        DevHandler.who = dict(DevHandler.who, perms=[], user="dev-none")
    elif args.bundle != "admin":
        if args.bundle not in BUNDLES:
            ap.error(f"unknown bundle {args.bundle!r}")
        DevHandler.who = dict(DevHandler.who, perms=sorted(BUNDLES[args.bundle]),
                              user=f"dev-{args.bundle}")
    FakeConnection.install(DevHandler.state, DevHandler.who)       # every agent call answered from the sample data
    server = ThreadingHTTPServer((args.bind, args.port), DevHandler)
    print(f"Fabric web UI DEV PREVIEW on http://{args.bind}:{args.port}/ — sample data, no sign-in, "
          "nothing is saved. Never expose this.", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
