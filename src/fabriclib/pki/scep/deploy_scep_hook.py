import filecmp
import os
import shutil
import subprocess

UNIT = "fabric-scep-hook"
UNIT_PATH = f"/etc/systemd/system/{UNIT}.service"


def deploy_scep_hook(v, render_tmp, deploy_base, unit_path=UNIT_PATH):
    """Purpose: install or remove the SCEP hook's host side (manual 1.5.3.3): its systemd unit and the socket folder
             nginx mounts; it follows the web console (install_webui), whose nginx server carries the hook's routes.
    Inputs:  v — rendered settings: install_webui, service_users.nginx.gid; render_tmp — where
             systemd/fabric-scep-hook.service was rendered (with the console); deploy_base — install root (/opt);
             unit_path — for tests.
    Returns: {"unit_changed": bool (installed or replaced: restart it), "removed": bool (stopped, disabled, deleted)}.
    Fails:   OSError copying the unit or making the folder; subprocess.TimeoutExpired from systemctl.
    Feeds:   deploy/apply_deployment (the caller reloads systemd and restarts or starts the unit).
    Notes:   <base>/scephook is root 0755, its run/ root:<nginx gid> 0750; the server makes the socket
             root:<nginx gid> 0660."""
    run_dir = os.path.join(deploy_base, "scephook", "run")
    if not v.get("install_webui"):
        if not os.path.exists(unit_path):
            return {"unit_changed": False, "removed": False}
        subprocess.run(["systemctl", "disable", "--now", UNIT], capture_output=True, timeout=60)
        os.remove(unit_path)
        shutil.rmtree(os.path.join(deploy_base, "scephook"), ignore_errors=True)
        return {"unit_changed": False, "removed": True}
    nginx_gid = int(v["service_users"]["nginx"]["gid"])
    os.makedirs(run_dir, mode=0o750, exist_ok=True)
    os.chown(os.path.join(deploy_base, "scephook"), 0, 0)
    os.chmod(os.path.join(deploy_base, "scephook"), 0o755)
    os.chown(run_dir, 0, nginx_gid)
    os.chmod(run_dir, 0o750)
    src = os.path.join(render_tmp, f"systemd/{UNIT}.service")
    if os.path.exists(unit_path) and filecmp.cmp(src, unit_path, shallow=False):
        return {"unit_changed": False, "removed": False}
    shutil.copy2(src, unit_path)
    os.chown(unit_path, 0, 0)
    os.chmod(unit_path, 0o644)
    return {"unit_changed": True, "removed": False}
