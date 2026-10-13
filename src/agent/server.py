#!/usr/bin/env python3
"""fabric-agent: the privileged half of the web UI.

Runs on the host as root (systemd `fabric-agent`) and serves a small JSON API
on a unix socket that is mounted into the unprivileged `webui` container.
It is deliberately not a general executor: every endpoint maps to one
fixed operation in fabriclib (one file per operation), inputs are validated there, and every change
is written to the audit log with the acting user. This file starts the server; the request handling
is agent/handler.py, the routes agent/get_route.py and agent/post_*.py.

Only peers whose uid is listed in --allow-uid (the fabric-web container user)
or root may connect; this is checked with SO_PEERCRED on every connection, on
top of the socket's 0660 root:<webui gid> permissions.

Every call from the web UI carries the signed-in person's Keycloak ID token
(Authorization: Bearer). The agent verifies it itself and allows the call
only if the token grants the permission the route needs
(fabriclib/rbac/required_permission.py; unlisted routes are refused). The
acting user in the audit log is the token's user, never a value from the
request. Root peers (the host itself) are not asked for a token.

  GET  /v1/version | /v1/services | /v1/zones | /v1/zones/<key> | /v1/audit
  POST /v1/zones {actor, name, hide_public} | /v1/zones/<key>/delete {actor, confirm}
  POST /v1/zones/<key>/records          {actor, type, name, ip|target|...}
  POST /v1/zones/<key>/records/delete   {actor, type, index, name}
  POST /v1/apply                        {actor}
  POST /v1/events                       {actor, action, detail}  (login audit)
  GET  /v1/pki/ca | /v1/pki/issued | /v1/tsig | /v1/reverse-zones
  POST /v1/pki/describe-csr             {actor, csr}
  POST /v1/pki/sign                     {actor, csr, days}
  POST /v1/pki/issue                    {actor, cn, sans, key_type, days}
  POST /v1/pki/inspect                  {actor, data}
  POST /v1/pki/convert                  {actor, cert, key}
  POST /v1/tsig                         {actor, name, zone, scope, hosts, types, secret}
  POST /v1/tsig/<name>/rotate | /v1/tsig/<name>/delete   {actor}
  GET  /v1/devices | /v1/people | /v1/vault | /v1/vault/slots | /v1/vault/devices
  POST /v1/vault/slots/<id>/test | /v1/vault/slots/<id>/remove | /v1/vault/rotate   {actor}
  POST /v1/vault/slots/add-usb      {actor, disk, label}
  POST /v1/vault/slots/add-security-key {actor, module, token, pin, key_id, label}
  POST /v1/vault/slots/add-hsm      {endpoint, key_id, ca, cert, key, server_name, label}
  POST /v1/devices {actor, name, fields} | /v1/devices/<name> {actor, fields} | /v1/devices/<name>/delete
  POST /v1/devices/<name>/certs      {actor, sha256, link}
  POST /v1/roles {actor, name, fields} | /v1/roles/<name> {actor, fields} | /v1/roles/<name>/delete
  POST /v1/people {uid, first, last, email} | /v1/people/<uid>/reset   (one-time password returned)
  GET  /v1/dhcp | POST /v1/dhcp/reservations {mac, ip, hostname} | /v1/dhcp/reservations/<mac>/delete
       POST /v1/dhcp/subnets {network, name, vlan, router, pools, notes} | /v1/dhcp/subnets/update {subnet, ...}
            | /v1/dhcp/subnets/delete {subnet, force} | /v1/dhcp/options {option, data, subnet|class|mac,
            always_send} | /v1/dhcp/options/delete | /v1/dhcp/classes {name, test, next_server, boot_file}
            | /v1/dhcp/classes/<name>/delete
  GET  /v1/radius | /v1/radius/guides (setup guides, Windows scripts) | /v1/radius/sessions
       POST /v1/radius/clients {name, address, message_authenticator, secret?, vendor?, transport?}
       | /v1/radius/clients/<name>/rotate {secret?} | /v1/radius/clients/<name>/delete   (secret returned once)
       | /v1/radius/clients/<name>/set {vendor?, transport?}
       | /v1/radius/sessions/disconnect {client, session} | /v1/radius/sessions/reauthenticate {client, session,
       bounce?}   (radius:coa)
       | /v1/radius/people {group, vlan, priority} | /v1/radius/people/<group>/delete
"""
import argparse
import os
import socketserver
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.handler import Handler  # noqa: E402


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    """Purpose: start fabric-agent: listen on the unix socket and serve requests, one thread each, until stopped.
    Inputs:  command-line --socket (path, required; an existing file there is removed), --socket-gid (int, required: the
             webui container's group), --allow-uid (int, repeatable: peer uids allowed besides root). Set by
             systemd/fabric-agent.service.j2 (socket <base>/webui/agent/agent.sock).
    Returns: never returns normally (serve_forever).
    Fails:   argparse exits 2 on missing/invalid arguments; OSError if the socket cannot be created, chowned or chmodded
             (must run as root).
    Feeds:   the fabric-agent systemd unit; src/webui/agentclient/ is its client.
    Notes:   the socket is created under umask 0117, then set to root:<socket-gid> 0660."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--socket-gid", type=int, required=True, help="group allowed to connect (webui container gid)")
    ap.add_argument("--allow-uid", type=int, action="append", default=[], help="peer uid allowed besides root")
    args = ap.parse_args()

    Handler.allowed_uids = {0, *args.allow_uid}
    if os.path.exists(args.socket):
        os.unlink(args.socket)
    old_umask = os.umask(0o117)
    try:
        server = UnixServer(args.socket, Handler)
    finally:
        os.umask(old_umask)
    os.chown(args.socket, 0, args.socket_gid)
    os.chmod(args.socket, 0o660)
    print(f"fabric-agent listening on {args.socket} (uids {sorted(Handler.allowed_uids)})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
