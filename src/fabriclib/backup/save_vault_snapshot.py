import http.client
import os
import socket
import ssl

from fabriclib.common.errors import ValidationError
from fabriclib.vault.common.approle_login import approle_login
from fabriclib.vault.constants import BACKUP_CREDS


def save_vault_snapshot(v, dest):
    """Purpose: OpenBao's data as a raft snapshot while it runs (manual 1.3.7.4): still encrypted by OpenBao's barrier,
             so only its vault key (the secrets section's other half) opens it. Taken with the fabric-backup AppRole,
             whose policy reads the snapshot and nothing else.
    Inputs:  v — vars, as bao_request reads them (ip_openbao, hostname_openbao, the root CA, openbao_key_dir);
             dest — the file to write (0600).
    Returns: the snapshot's size in bytes.
    Fails:   ValidationError when the login or the snapshot is refused (OpenBao sealed, the role not yet made: run
             `sudo fabricctl setup`), or OpenBao is unreachable; OSError writing dest.
    Feeds:   backup_plan (the secrets section online)."""
    token = approle_login(v, BACKUP_CREDS)
    root_ca = v.get("openbao_ca_file") or os.path.join(v["deploy_base_dir"], "stepca", "data", "certs", "root_ca.crt")
    ctx = ssl.create_default_context(cafile=root_ca)
    conn = http.client.HTTPSConnection(v["hostname_openbao"], v.get("openbao_port", 8200), timeout=120, context=ctx)
    try:
        sock = socket.create_connection((v["ip_openbao"], v.get("openbao_port", 8200)), 15)
        conn.sock = ctx.wrap_socket(sock, server_hostname=v["hostname_openbao"])
        conn.request("GET", "/v1/sys/storage/raft/snapshot", headers={"X-Vault-Token": token})
        resp = conn.getresponse()
        if resp.status != 200:
            why = resp.read(200).decode(errors="replace")
            raise ValidationError(f"OpenBao refused the snapshot ({resp.status}): {why}")
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        size = 0
        with os.fdopen(fd, "wb") as out:
            for chunk in iter(lambda: resp.read(1 << 20), b""):
                out.write(chunk)
                size += len(chunk)
    except (OSError, ssl.SSLError) as exc:
        raise ValidationError(f"OpenBao's snapshot could not be read: {exc}") from exc
    finally:
        conn.close()
    if size == 0:
        raise ValidationError("OpenBao returned an empty snapshot")
    return size
