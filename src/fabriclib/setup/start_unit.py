import subprocess

from fabriclib.common.systemctl_up import systemctl_up
from fabriclib.common.unit_settled import unit_settled
from fabriclib.common.wait_healthy import wait_healthy
from fabriclib.setup.errors import SetupError


def start_unit(unit, container, restart):
    """Purpose: enable a fabric unit (links it into multi-user.target and fabric.target), start or restart it,
             and wait for its container to be healthy (its failed state cleared first, so systemd's start limit
             never refuses the start; a unit that is not cleanly active is stopped first, ending any restart loop;
             a unit systemd is already starting or stopping is waited for first, never interrupted; a start cut
             short from outside, as by systemd re-executing, is waited for and tried once more only if the unit
             did not come up by itself: common/systemctl_up).
    Inputs:  unit — systemd unit name; container — its container name; restart — bool, restart when already
             active (config, certificate or image changed).
    Returns: "running" (active and no restart asked; health not checked), "started" or "restarted".
    Fails:   CalledProcessError from `systemctl enable`, or from the second start when the first failed and the unit
             did not come up; SetupError when the container is not healthy within 900 s (last 40 log lines included).
    Feeds:   start_services.run, setup_openbao.run, images.switch_image."""
    subprocess.run(["systemctl", "enable", unit], check=True, capture_output=True)
    unit_settled(unit)
    active = subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0
    if active and not restart:
        return "running"
    # a unit that kept failing (a bad image restarted until systemd's start limit) refuses a start until its failed
    # state is cleared, and one still in its automatic-restart loop races a start: it is stopped first, which cancels
    # the pending restart (the rollback after a failed image update hit both now and then: manual 2.3.6.1.27, 2.3.6.2.9)
    if not active:
        subprocess.run(["systemctl", "stop", unit], capture_output=True)
    subprocess.run(["systemctl", "reset-failed", unit], capture_output=True)
    systemctl_up([unit], restart=active)
    healthy, why = wait_healthy(container, timeout=900)
    if not healthy:
        logs = subprocess.run(["docker", "logs", "--tail", "40", container], capture_output=True, text=True)
        raise SetupError(f"{container} did not become healthy ({why}):\n{logs.stdout}{logs.stderr}")
    return "restarted" if active else "started"
