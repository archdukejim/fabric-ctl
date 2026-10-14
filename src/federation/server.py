#!/usr/bin/env python3
"""fabric-federation: the federation endpoint (manual 1.9.4.2).

A separate, minimal root service, deliberately not part of fabric-agent: it
is the only fabric API that peers on the network reach (through nginx,
https://federation.<domain>), so it serves only what other sites need. It
listens on a unix socket mounted into the nginx container; only nginx's uid
and root may connect (SO_PEERCRED), on top of the socket's 0660
root:<nginx gid> permissions. Every route maps to one fabriclib operation.

  GET  /v1/health    {"ok": true, "site": <site_name>}
  POST /v1/join      {id, secret, site, csr, domain, address, federation_host, via}
                     -> fabriclib/federation/accept_join (the invitation's one-time secret authenticates the
                     call), or relay_join when "via" names this site (it forwards to its upstream)
  POST /v1/dc-type   {id, secret, site, to} -> fabriclib/federation/accept_dc_type (a site's DC type change,
                     2.1.9.23: the change token's one-time secret authenticates the call)
"""
import argparse
import json
import os
import socket
import socketserver
import struct
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.load_vars import load_vars  # noqa: E402
from fabriclib.federation.accept_dc_type import accept_dc_type  # noqa: E402
from fabriclib.federation.accept_join import accept_join  # noqa: E402
from fabriclib.federation.constants import JOIN_BODY_MAX  # noqa: E402
from fabriclib.federation.relay_join import relay_join  # noqa: E402
from fabriclib.system.apply_changes import apply_changes  # noqa: E402


class Handler(BaseHTTPRequestHandler):
    server_version = "fabric-federation"

    @staticmethod
    def after_join(site):
        """Purpose: after a site joined here: apply in the background, so its DNS delegation, secondary zone and
                 TSIG key take effect (manual 1.9 M4). The join was answered already.
        Inputs:  site — str, the site that joined (the apply's actor is "site:<site>").
        Returns: None; a daemon thread runs apply_changes.
        Fails:   never here (the apply's own result is audited by apply_changes).
        Feeds:   do_POST. Tests set Handler.after_join = None: they run this handler outside an install."""
        threading.Thread(target=apply_changes, args=(f"site:{site}", "federation"), daemon=True).start()
    sys_version = ""

    def log_message(self, fmt, *args):
        """Purpose: write one request log line to stderr (the systemd journal), with the client nginx saw.
        Inputs:  fmt — %-format string; args — its values (from BaseHTTPRequestHandler).
        Returns: None.
        Fails:   never in practice.
        Feeds:   BaseHTTPRequestHandler (every request and error)."""
        sys.stderr.write(f"{self.client_ip()} {fmt % args}\n")

    def client_ip(self):
        """Purpose: the network client's address: X-Real-IP, which nginx always overwrites.
        Inputs:  none (self.headers, when parsed).
        Returns: str, "-" when unknown.
        Fails:   never.
        Feeds:   log_message, do_POST (the audit's from=)."""
        headers = getattr(self, "headers", None)
        return (headers.get("X-Real-IP") if headers else None) or "-"

    def reply(self, status, obj):
        """Purpose: send a complete JSON response.
        Inputs:  status — int HTTP status; obj — JSON-serialisable.
        Returns: None.
        Fails:   OSError (BrokenPipeError) if the peer has gone.
        Feeds:   do_GET, do_POST."""
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """Purpose: GET /v1/health — is the endpoint up, and which site answers.
        Inputs:  the request path.
        Returns: None; 200 {"ok": true, "site"} or 404 {"error": "not found"}.
        Fails:   OSError writing the reply; yaml/OSError from load_vars become a 500.
        Feeds:   nginx (federation.<domain>), joining sites and `fabricctl doctor` later."""
        if self.path != "/v1/health":
            return self.reply(404, {"error": "not found"})
        try:
            self.reply(200, {"ok": True, "site": load_vars().get("site_name")})
        except Exception:  # noqa: BLE001 — never leak details to the network
            traceback.print_exc()
            self.reply(500, {"error": "internal error"})

    def do_POST(self):
        """Purpose: POST /v1/join — an invited site joins (accept_join).
        Inputs:  a JSON body of at most JOIN_BODY_MAX bytes.
        Returns: None; 200 with accept_join's answer (or relay_join's, when the request's via names this site), then
                 an apply in the background after a join here (the new site's DNS delegation and zones); 400 {"error":
                 message} for a refusal (ValidationError) or a
                 bad body; 413 when too large; 404 for any other path; 500 {"error": "internal error"} otherwise
                 (details only in the journal).
        Fails:   OSError writing the reply.
        Feeds:   nginx (federation.<domain>) <- join_upstream on the joining node; POST /v1/dc-type (a site's DC type
                 change, 2.1.9.23: accept_dc_type, its token authenticating the call) <- federation/change_dc_type."""
        if self.path not in ("/v1/join", "/v1/dc-type"):
            return self.reply(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > JOIN_BODY_MAX:
            return self.reply(413, {"error": "request too large"})
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
            v = load_vars()
            if self.path == "/v1/dc-type":
                return self.reply(200, accept_dc_type(v, req, client_ip=self.client_ip()))
            relay =isinstance(req, dict) and req.get("via") and req.get("via") == v.get("site_name")
            self.reply(200, (relay_join if relay else accept_join)(v, req, client_ip=self.client_ip()))
            if not relay and self.after_join:     # the new site's delegation, secondary zone and key
                self.after_join(req.get("site", "?"))
        except (ValidationError, ValueError) as e:
            self.reply(400, {"error": str(e) if isinstance(e, ValidationError) else "the body is not JSON"})
        except Exception:  # noqa: BLE001 — never leak details to the network
            traceback.print_exc()
            self.reply(500, {"error": "internal error"})


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allowed_uids = {0}

    def verify_request(self, request, client_address):
        """Purpose: accept a connection only from root or nginx's uid (SO_PEERCRED, kernel-supplied).
        Inputs:  request — the connected socket; client_address — unused (unix sockets have none).
        Returns: bool.
        Fails:   never: an unreadable peer is refused.
        Feeds:   socketserver, before each request is handled."""
        try:
            creds = request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        except OSError:
            return False
        return struct.unpack("3i", creds)[1] in self.allowed_uids


def main():
    """Purpose: start fabric-federation: listen on the unix socket and serve requests, one thread each.
    Inputs:  command-line --socket (path, required; an existing file there is removed), --socket-gid (int, required:
             nginx's group), --allow-uid (int, repeatable: nginx's uid). Set by systemd/fabric-federation.service.j2.
    Returns: never returns normally (serve_forever).
    Fails:   argparse exits 2 on bad arguments; OSError if the socket cannot be created, chowned or chmodded.
    Feeds:   the fabric-federation systemd unit; nginx's federation.<domain> vhost proxies to it.
    Notes:   the socket is created under umask 0117, then set to root:<socket-gid> 0660."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--socket-gid", type=int, required=True)
    ap.add_argument("--allow-uid", type=int, action="append", default=[])
    args = ap.parse_args()
    UnixServer.allowed_uids = {0, *args.allow_uid}
    if os.path.exists(args.socket):
        os.unlink(args.socket)
    old_umask = os.umask(0o117)
    try:
        server = UnixServer(args.socket, Handler)
    finally:
        os.umask(old_umask)
    os.chown(args.socket, 0, args.socket_gid)
    os.chmod(args.socket, 0o660)
    print(f"fabric-federation listening on {args.socket} (uids {sorted(UnixServer.allowed_uids)})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
