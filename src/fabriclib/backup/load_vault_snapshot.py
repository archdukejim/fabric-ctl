import http.client
import os
import socket
import ssl

from fabriclib.backup.restore_pending import read_restore_pending, write_restore_pending
from fabriclib.common.errors import ValidationError


def load_vault_snapshot(v, config_dir, root_token):
    """Purpose: right after setup initialises OpenBao on a host restored from an online bundle (manual 1.3.7.6): the
             bundle's raft snapshot forced onto the new cluster with its one-time root token. OpenBao reopens on the
             bundle's data with the bundle's vault key (restored with it), where that token is unknown: the caller
             deletes it and goes on with the bundle's own AppRoles.
    Inputs:  v — vars (as bao_request reads them); config_dir — fabric's config folder; root_token — the new
             cluster's initial root token.
    Returns: True when a snapshot was loaded, False when none was pending.
    Fails:   ValidationError when OpenBao refuses it or cannot be reached (the snapshot stays pending); OSError.
    Feeds:   setup/setup_openbao (after init_openbao)."""
    pending = read_restore_pending(config_dir)
    snap = pending.get("secrets")
    if not snap:
        return False
    root_ca = v.get("openbao_ca_file") or os.path.join(v["deploy_base_dir"], "stepca", "data", "certs", "root_ca.crt")
    ctx = ssl.create_default_context(cafile=root_ca)
    conn = http.client.HTTPSConnection(v["hostname_openbao"], v.get("openbao_port", 8200), timeout=300, context=ctx)
    try:
        sock = socket.create_connection((v["ip_openbao"], v.get("openbao_port", 8200)), 15)
        conn.sock = ctx.wrap_socket(sock, server_hostname=v["hostname_openbao"])
        with open(snap, "rb") as f:
            body = f.read()
        conn.request("POST", "/v1/sys/storage/raft/snapshot-force", body=body,
                     headers={"X-Vault-Token": root_token, "Content-Type": "application/octet-stream"})
        resp = conn.getresponse()
        why = resp.read(300).decode(errors="replace")
    except (OSError, ssl.SSLError) as exc:
        raise ValidationError(f"OpenBao's snapshot could not be loaded: {exc}") from exc
    finally:
        conn.close()
    if resp.status not in (200, 204):
        raise ValidationError(f"OpenBao refused the bundle's snapshot ({resp.status}): {why}")
    pending.pop("secrets")
    write_restore_pending(config_dir, pending)
    os.remove(snap)
    return True
