#!/usr/bin/env python3
"""fabric-scep-hook: Step-CA's SCEP webhooks (manual 1.5.3.3).

A separate, minimal root service, like fabric-federation: Step-CA calls it
through nginx (https://<hostname_mgr>/hooks/scep/..., the web console's
name, which asks for a client certificate), and it answers only Step-CA's
own certificate (fabriclib/pki/scep/answer_hook). It listens on a unix
socket mounted into the nginx container; only nginx's uid and root may
connect (SO_PEERCRED), on top of the socket's 0660 root:<nginx gid>.

  POST /hooks/scep/challenge   SCEPCHALLENGE: may this request be signed? (a one-time challenge)
  POST /hooks/scep/issued      NOTIFYING: the certificate issued, recorded and linked to its device
"""
import argparse
import json
import os
import socket
import socketserver
import struct
import sys
import traceback
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.load_vars import load_vars  # noqa: E402
from fabriclib.pki.scep.answer_hook import answer_hook  # noqa: E402

BODY_MAX = 64 * 1024


class Handler(BaseHTTPRequestHandler):
    """One webhook call from Step-CA (through nginx): the body read, answer_hook asked, its answer sent."""
    server_version = "fabric-scep-hook"
    sys_version = ""

    def log_message(self, fmt, *args):
        """Purpose: write one request log line to stderr (the systemd journal).
        Inputs:  fmt — %-format string; args — its values (from BaseHTTPRequestHandler).
        Returns: None.
        Fails:   never in practice.
        Feeds:   BaseHTTPRequestHandler (every request and error)."""
        sys.stderr.write(f"{fmt % args}\n")

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
        """Purpose: refuse every GET: the hooks are POST only.
        Inputs:  none.
        Returns: None; 404.
        Fails:   OSError writing the reply.
        Feeds:   nginx."""
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        """Purpose: one webhook call: the JSON body (at most BODY_MAX bytes) and nginx's client-certificate headers
                 (X-SSL-Client-Verify, X-SSL-Client-Cert, always set by nginx) to answer_hook.
        Inputs:  the request.
        Returns: None; answer_hook's (status, answer); 413 when too large; 400 for a body that is not JSON or a
                 refusal (ValidationError); 500 {"error": "internal error"} otherwise (details only in the journal).
                 Step-CA refuses the request on anything but an allowing 200.
        Fails:   OSError writing the reply.
        Feeds:   nginx (hostname_mgr, /hooks/scep/) <- Step-CA's webhook client."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > BODY_MAX:
            return self.reply(413, {"error": "request too large"})
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            status, answer = answer_hook(load_vars(), self.path, self.headers.get("X-SSL-Client-Verify", ""),
                                         self.headers.get("X-SSL-Client-Cert", ""), body)
            self.reply(status, answer)
        except (ValidationError, ValueError) as e:
            self.reply(400, {"error": str(e) if isinstance(e, ValidationError) else "the body is not JSON"})
        except Exception:  # noqa: BLE001 — never leak details
            traceback.print_exc()
            self.reply(500, {"error": "internal error"})


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """The hook's unix socket server: one thread per call, only root and nginx's uid connect."""
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
    """Purpose: start fabric-scep-hook: listen on the unix socket and serve requests, one thread each.
    Inputs:  command-line --socket (path, required; an existing file there is removed), --socket-gid (int, required:
             nginx's group), --allow-uid (int, repeatable: nginx's uid). Set by systemd/fabric-scep-hook.service.j2.
    Returns: never returns normally (serve_forever).
    Fails:   argparse exits 2 on bad arguments; OSError if the socket cannot be created, chowned or chmodded.
    Feeds:   the fabric-scep-hook systemd unit; nginx's web console server proxies /hooks/scep/ to it.
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
    print(f"fabric-scep-hook listening on {args.socket} (uids {sorted(UnixServer.allowed_uids)})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
