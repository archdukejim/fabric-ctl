import subprocess

from fabriclib.common.systemctl_up import systemctl_up

# How each service takes a renewed certificate (manual 2.1.5.4): a signal where the program re-reads its certificate
# without dropping anything, nothing where it watches the file itself, a restart (seconds) otherwise.
HUP = {"nginx", "postgres", "openbao"}        # nginx and Postgres reload; OpenBao re-reads its listener (no reseal)
# Keycloak re-reads its certificate files by itself (https-certificates-reload-period)
ON_ITS_OWN = {"keycloak"}


def pick_up_cert(unit):
    """Purpose: make a running service use its renewed certificate, with as little interruption as it allows.
    Inputs:  unit — a fabric service (its systemd unit and container have the same name).
    Returns: "reloaded", "picks it up itself", "restarted", or "not running" (it reads the new one when it starts).
    Fails:   subprocess.CalledProcessError when the signal or the restart fails.
    Feeds:   setup/renew_service_certs."""
    if subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode != 0:
        return "not running"
    if unit in ON_ITS_OWN:
        return "picks it up itself"
    if unit in HUP:
        subprocess.run(["docker", "kill", "--signal", "HUP", unit], check=True, capture_output=True)
        return "reloaded"
    systemctl_up([unit], restart=True)
    return "restarted"
