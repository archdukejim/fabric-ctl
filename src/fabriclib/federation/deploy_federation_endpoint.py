import os
import shutil
import subprocess

from fabriclib.common.same_content import same_content

UNIT = "fabric-federation"
UNIT_PATH = f"/etc/systemd/system/{UNIT}.service"


def deploy_federation_endpoint(v, render_tmp, deploy_base):
    """Purpose: install or remove the federation endpoint's host side (manual 1.9.4.2): its systemd
             unit and the socket directory nginx mounts. The nginx vhost and the CNAME follow
             federation_endpoint in their own templates.
    Inputs:  v — rendered vars: federation_endpoint, service_users.nginx.gid; render_tmp — where
             systemd/fabric-federation.service was rendered (when on); deploy_base — install root (e.g. /opt).
    Returns: {"unit_changed": bool (installed or replaced: restart it), "removed": bool (stopped, disabled and
             deleted because the endpoint was turned off)}.
    Fails:   OSError copying the unit or creating the directory; subprocess.TimeoutExpired from systemctl.
    Feeds:   deploy/apply_deployment (the caller runs daemon-reload and restarts or starts the unit).
    Notes:   the socket directory <base>/federation/run is root:<nginx gid> 0750; the server makes the socket
             root:<nginx gid> 0660."""
    run_dir = os.path.join(deploy_base, "federation", "run")
    if not v.get("federation_endpoint"):
        if not os.path.exists(UNIT_PATH):
            return {"unit_changed": False, "removed": False}
        subprocess.run(["systemctl", "disable", "--now", UNIT], capture_output=True, timeout=60)
        os.remove(UNIT_PATH)
        shutil.rmtree(os.path.join(deploy_base, "federation"), ignore_errors=True)
        return {"unit_changed": False, "removed": True}
    nginx_gid = int(v["service_users"]["nginx"]["gid"])
    os.makedirs(run_dir, mode=0o750, exist_ok=True)
    os.chown(os.path.join(deploy_base, "federation"), 0, 0)
    os.chmod(os.path.join(deploy_base, "federation"), 0o755)
    os.chown(run_dir, 0, nginx_gid)
    os.chmod(run_dir, 0o750)
    src = os.path.join(render_tmp, f"systemd/{UNIT}.service")
    if os.path.exists(UNIT_PATH) and same_content(src, UNIT_PATH):
        return {"unit_changed": False, "removed": False}
    shutil.copy2(src, UNIT_PATH)
    os.chown(UNIT_PATH, 0, 0)
    os.chmod(UNIT_PATH, 0o644)
    return {"unit_changed": True, "removed": False}
