import shutil
import subprocess

from fabriclib.common.errors import ValidationError

PROGRAMS = {"kea-dhcp4.conf": "/usr/sbin/kea-dhcp4", "kea-dhcp-ddns.conf": "/usr/sbin/kea-dhcp-ddns"}


def check_kea_config(image, name, text):
    """Purpose: have Kea itself check a configuration before fabric installs it (`kea-dhcp4 -t`, manual 1.10.2.4): a
                file Kea would refuse is never put in place.
    Inputs:  image — fabric's Kea image (vars image_kea); name — "kea-dhcp4.conf" or "kea-dhcp-ddns.conf";
             text — the rendered configuration.
    Returns: True when Kea accepted it; None when it could not be checked (no Docker, or the image is not built
             yet — a first install: the service start then reports any error).
    Fails:   ValidationError with Kea's own message when it refuses the file; subprocess.TimeoutExpired (60 s).
    Feeds:   dhcp/deploy_kea.
    Notes:   runs in a throwaway container on the host network (Kea checks the served interfaces exist; `-t` opens
             no socket), with no capabilities and a read-only root. The file goes in on stdin, into the container's
             own /tmp: no host path is mounted, because the Docker daemon cannot see the caller's private /tmp
             (fabric-agent's PrivateTmp: every console apply that changed Kea's file failed with "Unable to open
             file /check/kea-dhcp4.conf", 2.3.10.11.16)."""
    if not shutil.which("docker") or subprocess.run(["docker", "image", "inspect", image],
                                                    capture_output=True).returncode != 0:
        return None
    res = subprocess.run(["docker", "run", "--rm", "-i", "--network", "host", "--cap-drop", "ALL", "--read-only",
                          "--security-opt", "no-new-privileges:true", "--tmpfs", "/run/kea", "--tmpfs",
                          "/var/run/kea", "--tmpfs", "/tmp", "--entrypoint", "/bin/sh", image, "-c",
                          f'cat > "/tmp/{name}" && exec {PROGRAMS[name]} -t "/tmp/{name}"'],
                         input=text, capture_output=True, text=True, timeout=60)
    if res.returncode != 0:
        lines = [x for x in (res.stdout + res.stderr).splitlines() if "ERROR" in x or "error" in x.lower()]
        raise ValidationError(f"Kea refused the new {name}: " + (" | ".join(lines[-3:]) or res.stderr[-400:])
                              + " — nothing was changed")
    return True
