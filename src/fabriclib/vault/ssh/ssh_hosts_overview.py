import datetime
import os

from fabriclib.common.errors import ValidationError
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.vault.ssh.constants import HOST_PUBLISHED, RENEW_DAYS
from fabriclib.vault.ssh.parse_ssh_cert import parse_ssh_cert
from fabriclib.vault.ssh.parse_ssh_key import parse_ssh_key


def _state(h, ca_fp, now):
    """Purpose: one machine's host certificate state, in words the console shows.
    Inputs:  h — one list_ssh_hosts entry; ca_fp — the published host CA's fingerprint ("" when off); now — int.
    Returns: {"state": "valid" | "renewing" | "expired" | "other CA" | "awaiting signing" | "not published" |
             "not managed" | "disabled", "until" (ISO date of the latest valid certificate, or ""), "principals",
             "types" (the key types it published)}.
    Fails:   never (a certificate that does not parse counts as none).
    Feeds:   ssh_hosts_overview."""
    types = []
    for k in h["keys"]:
        try:
            types.append(parse_ssh_key(k)["type"])
        except ValidationError:
            continue
    best = None
    for c in h["certs"]:
        try:
            p = parse_ssh_cert(c)
        except ValidationError:
            continue
        if best is None or p["valid_before"] > best["valid_before"]:
            best = p
    until = (datetime.datetime.fromtimestamp(best["valid_before"], datetime.timezone.utc).date().isoformat()
             if best else "")
    if not h["enabled"]:
        state = "disabled"
    elif not h["managed"]:
        state = "not managed"
    elif not h["keys"]:
        state = "not published"
    elif best is None:
        state = "awaiting signing"
    elif ca_fp and best["ca_fingerprint"] != ca_fp:
        state = "other CA"
    elif best["valid_before"] <= now:
        state = "expired"
    elif best["valid_before"] - now <= RENEW_DAYS * 86400:
        state = "renewing"
    else:
        state = "valid"
    return {"state": state, "until": until, "principals": best["principals"] if best else [], "types": types}


def ssh_hosts_overview(v, op=None, now=None):
    """Purpose: the SSH page's host certificates (manual 1.6.11.9.11): the host CA's public key and fingerprint as
             machines fetch it, and each machine of the site with its certificate's state.
    Inputs:  v — settings: ssh_certificates, deploy_base_dir, and run_op's; op — op(name, args) (None: run_op with
             load_secrets()); now — int seconds since 1970 UTC (None: now).
    Returns: {"on": bool, "public_key" ("" when off), "fingerprint", "machines": [{"name", "ou", "managed",
             "state", "until", "principals", "types"}]} (no machines while off: nothing is signed then).
    Fails:   ValidationError from run_op (the directory unreachable) or load_secrets (OpenBao locked); OSError
             reading the published key.
    Feeds:   agent route GET /v1/ssh/hosts <- the web console's SSH page."""
    on = bool(v.get("ssh_certificates"))
    path = os.path.join(v["deploy_base_dir"], "nginx", "www", "certs", HOST_PUBLISHED)
    key = ""
    if on and os.path.exists(path):
        with open(path) as f:
            key = f.read().strip()
    try:
        fingerprint = parse_ssh_key(key)["fingerprint"] if key else ""
    except ValidationError:
        key, fingerprint = "", ""
    if not on:
        return {"on": False, "public_key": "", "fingerprint": "", "machines": []}
    if op is None:
        secrets = load_secrets()
        op = lambda name, args: run_op(v, secrets, name, args)      # noqa: E731
    now = int(now if now is not None else datetime.datetime.now(datetime.timezone.utc).timestamp())
    machines = [{"name": h["name"], "ou": h["ou"], "managed": h["managed"], **_state(h, fingerprint, now)}
                for h in op("list_ssh_hosts", {})]
    return {"on": True, "public_key": key, "fingerprint": fingerprint, "machines": machines}
