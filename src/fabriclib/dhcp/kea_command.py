import json
import os
import socket

from fabriclib.common.errors import ValidationError

# each daemon's control socket, host side under <deploy_base>/kea (kea-ddns's since 2.1.10.45: its config-reload)
SOCKETS = {"dhcp4": ("run", "kea4-ctrl-socket"), "ddns": ("run-ddns", "kea-ddns-ctrl-socket")}


def kea_command(v, command, arguments=None, timeout=10, daemon="dhcp4"):
    """Purpose: Send one command to a Kea daemon over its control socket (host side
             <deploy_base>/kea/run/kea4-ctrl-socket for kea-dhcp4,
             <deploy_base>/kea/run-ddns/kea-ddns-ctrl-socket for kea-dhcp-ddns; root only).
    Inputs:  v — the vars dict (deploy_base_dir).
             command — str Kea command, e.g. "lease4-get-all".
             arguments — dict, sent only when not empty.
             timeout — seconds per socket operation (default 10).
             daemon — "dhcp4" (default) or "ddns".
    Returns: the response's "arguments" dict, or {} (result 0 = ok, 3 = empty).
    Fails:   ValidationError "Kea is not answering (…): sudo fabricctl status" (OSError or timeout), "Kea sent no answer
             to …", "Kea refused …: <text>"; IndexError on an empty list response.
    Feeds:   list_leases, reload_kea (config-reload).
    """
    path = os.path.join(v["deploy_base_dir"], "kea", *SOCKETS[daemon])
    req = {"command": command, **({"arguments": arguments} if arguments else {})}
    resp = None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(path)
            s.sendall(json.dumps(req).encode())
            data = b""
            while resp is None:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
                try:
                    resp = json.loads(data)
                except ValueError:
                    continue
    except OSError as exc:
        raise ValidationError(f"Kea is not answering ({exc}): sudo fabricctl status")
    if resp is None:
        raise ValidationError(f"Kea sent no answer to {command}")
    if isinstance(resp, list):
        resp = resp[0]
    if resp.get("result") not in (0, 3):                   # 3 = empty (e.g. no leases yet)
        raise ValidationError(f"Kea refused {command}: {resp.get('text', '')}")
    return resp.get("arguments") or {}
