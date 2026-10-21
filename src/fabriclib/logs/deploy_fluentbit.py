import os

from fabriclib.common.errors import ValidationError


def _write(path, text, mode, uid=0, gid=0):
    """Purpose: Write a file atomically with an owner and mode unless it already holds exactly that text.
    Inputs:  path — str; text — str; mode — int permission bits for the new temp file; uid, gid — owner (default root).
    Returns: True if written, False if unchanged.
    Fails:   OSError from open, chown or replace.
    Feeds:   deploy_fluentbit.
    Notes:   duplicates fabriclib/common/write_file_if_changed.py without its chmod, so the mode is subject to umask and
             not reset on a leftover .tmp file.
    """
    if os.path.exists(path) and open(path).read() == text:
        return False
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chown(path + ".tmp", uid, gid)
    os.replace(path + ".tmp", path)
    return True


def deploy_fluentbit(v, secrets, jinja_env):
    """Purpose: Write Fluent Bit's files under <deploy_base>/fluentbit: its config, the CA certificates that verify each
             destination, the credentials file docker reads for the container, and the disk buffer folder.
    Inputs:  v — the rendered vars: deploy_base_dir, service_users.fluentbit uid/gid, log_forwarding (syslog / elastic,
             each with an optional ca_file) and what the template uses.
             secrets — fabric's secrets dict (log_elastic_password).
             jinja_env — Jinja environment holding fluentbit/fluent-bit.yaml.j2 (templates).
    Returns: True if any file changed (the service must restart), else False.
    Fails:   ValidationError "log_forwarding.<name>.ca_file … not found" (a destination's ca_file, or the fabric root CA
             used by default, is missing; nothing is written then); KeyError on missing vars; OSError; jinja2 errors.
    Feeds:   deploy/deploy_optional_parts (apply), setup/start_services (a fresh install, after the PKI step),
             run_logs_command (set-password elastic); tests/fluentbit/run.py.
    Notes:   config/ is root:fluentbit 0750 and buffer/ fluentbit 0750; the config and CA files are 0640, secrets.env
             root 0600. Both CA files are written even for a destination that is not configured.
    """
    fabric_ca = os.path.join(v["deploy_base_dir"], "stepca", "data", "certs", "root_ca.crt")
    lf = v.get("log_forwarding") or {}
    sources = {name: (lf.get(name) or {}).get("ca_file") or fabric_ca for name in ("syslog", "elastic")}
    for name, src in sources.items():      # checked before anything is written
        if not os.path.isfile(src):
            raise ValidationError(f"log_forwarding.{name}.ca_file {src} not found")
    base = os.path.join(v["deploy_base_dir"], "fluentbit")
    uid, gid = (int(v["service_users"]["fluentbit"][k]) for k in ("uid", "gid"))
    for sub, owner, mode in (("config", (0, gid), 0o750), ("buffer", (uid, gid), 0o750)):
        path = os.path.join(base, sub)
        os.makedirs(path, mode=mode, exist_ok=True)
        os.chown(path, *owner)
        os.chmod(path, mode)
    cfg = os.path.join(base, "config")
    changed = _write(os.path.join(cfg, "fluent-bit.yaml"),
                     jinja_env.get_template("fluentbit/fluent-bit.yaml.j2").render(**v), 0o640, 0, gid)
    for name, src in sources.items():
        changed |= _write(os.path.join(cfg, f"{name}-ca.crt"), open(src).read(), 0o640, 0, gid)
    env = f"LOG_ELASTIC_PASSWORD={secrets.get('log_elastic_password', '')}\n"
    changed |= _write(os.path.join(cfg, "secrets.env"), env, 0o600)
    return changed
