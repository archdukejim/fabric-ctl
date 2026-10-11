import hashlib
import json
import os

import bcrypt

from fabriclib.common.ensure_dir import ensure_dir
from fabriclib.common.errors import ValidationError
from fabriclib.common.service_user import service_user
from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.dns_filter.common.adguard_desired import adguard_desired
from fabriclib.dns_filter.common.adguard_paths import adguard_paths
from fabriclib.dns_filter.sync_adguard import sync_adguard

TEMPLATE = "dnsfilter/AdGuardHome.yaml.j2"


def _record(path):
    """Purpose: fabric's record of its last render of AdGuard's file.
    Inputs:  path — adguard_paths' "render".
    Returns: {"hash": the password's bcrypt hash, "static": SHA-256 of the parts the API cannot change}, or {}.
    Fails:   never.
    Feeds:   deploy_adguard."""
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def deploy_adguard(v, secrets, jinja_env, sync=True):
    """Purpose: AdGuard Home's deploy step (manual 1.12.3.3, 1.12.3.4): its folders and AdGuardHome.yaml, rendered by
             fabric so it never has a first launch. AdGuard rewrites that file when its API changes it, so fabric keeps
             a record of its own render: when a part the API cannot change differs (ports, the certificate, its
             account, blocking), the whole file is written and AdGuard restarted; otherwise the running AdGuard is
             made to match through its API (sync_adguard) and nothing restarts.
    Inputs:  v — checked vars (deploy_base_dir, domain, ip_resolver, ip_adguard, service_users.adguard and what
             adguard_desired reads); secrets — adguard_api_password; jinja_env — fabric's template environment;
             sync — False to leave a running AdGuard alone (tests, a first install).
    Returns: {"restart": bool (the file was written for a change outside the API, or it had none yet), "synced": the
             API changes made, or None when AdGuard was not answering (it reads the file at its next start: the
             file is written then too), "error": why the sync stopped, or None}.
    Fails:   KeyError for a missing secret or var; OSError writing the files; jinja2 errors.
    Feeds:   deploy/deploy_optional_parts (when install_resolver); tests/resolver/run.py."""
    paths = adguard_paths(v)
    uid, gid = service_user(v, "adguard")
    ensure_dir(paths["root"], 0o750, 0, gid)
    ensure_dir(paths["conf"], 0o750, uid, gid)          # AdGuard rewrites its file there
    ensure_dir(paths["work"], 0o750, uid, gid)
    ensure_dir(paths["lists"], 0o750, 0, gid)           # read-only to it: fabric's copies
    ensure_dir(paths["tls"], 0o750, uid, gid)           # as install_cert leaves it (mint_service_certs)
    password = secrets["adguard_api_password"]
    record = _record(paths["render"])
    pw_hash = record.get("hash") or ""
    if not pw_hash or not bcrypt.checkpw(password.encode(), pw_hash.encode()):
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()
    want = adguard_desired(v)
    tls = all(os.path.exists(os.path.join(paths["tls"], f)) for f in ("fullchain.pem", "privkey.pem"))
    ctx = {**v, **want, "adguard_password_hash": pw_hash, "tls": tls}
    template = jinja_env.get_template(TEMPLATE)
    static = hashlib.sha256(template.render(**ctx, with_api=False).encode()).hexdigest()
    whole = template.render(**ctx, with_api=True)
    restart = static != record.get("static") or not os.path.exists(paths["config"])
    synced, error = None, None
    if not restart and sync:
        try:
            synced = sync_adguard(v, password)
        except ValidationError as e:
            error = str(e)
    if restart or synced is None:
        # read at its next start; a running AdGuard is restarted by the apply only for a change outside the API
        write_file_if_changed(paths["config"], whole, 0o600, uid, gid)
    write_file_if_changed(paths["render"], json.dumps({"hash": pw_hash, "static": static}) + "\n", 0o600)
    return {"restart": restart, "synced": synced, "error": error}
