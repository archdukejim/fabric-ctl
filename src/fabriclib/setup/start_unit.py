import subprocess
import time

from fabriclib.common.wait_healthy import wait_healthy
from fabriclib.setup.errors import SetupError

# a unit between states: systemd is starting or stopping it (its own restart of a dependent among them)
MOVING = ("activating", "deactivating", "reloading")


def _unit_state(unit):
    """Purpose: a unit's ActiveState and SubState as systemd reports them.
    Inputs:  unit — systemd unit name.
    Returns: (active state, sub state), e.g. ("activating", "start-post"); ("", "") when systemctl answers nothing.
    Fails:   never (systemctl's own failure reads as ("", "")).
    Feeds:   _settled."""
    out = subprocess.run(["systemctl", "show", "-p", "ActiveState", "-p", "SubState", unit],
                         capture_output=True, text=True).stdout or ""
    vals = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return vals.get("ActiveState", ""), vals.get("SubState", "")


def _settled(unit, timeout=660, pause=2.0):
    """Purpose: wait while systemd is starting or stopping a unit, so a start of fabric's never interrupts one that
             is under way (2.3.2.5: restarting Postgres makes systemd restart Keycloak, which Requires it; a stop
             sent to Keycloak mid-start raced its container's removal and failed the start). A unit waiting in its
             automatic-restart loop is not waited for: it is in a loop, not on its way.
    Inputs:  unit — systemd unit name; timeout — seconds (a fabric unit's start allows 600, its health check after);
             pause — seconds between looks.
    Returns: (active state, sub state) once it no longer moves, or as it is at the timeout.
    Fails:   never.
    Feeds:   start_unit."""
    deadline = time.monotonic() + timeout
    while True:
        state, sub = _unit_state(unit)
        if state not in MOVING or sub == "auto-restart" or time.monotonic() >= deadline:
            return state, sub
        time.sleep(pause)


def start_unit(unit, container, restart):
    """Purpose: enable a fabric unit (links it into multi-user.target and fabric.target), start or restart it,
             and wait for its container to be healthy (its failed state cleared first, so systemd's start limit
             never refuses the start; a unit that is not cleanly active is stopped first, ending any restart loop;
             a unit systemd is already starting or stopping is waited for first, never interrupted).
    Inputs:  unit — systemd unit name; container — its container name; restart — bool, restart when already
             active (config, certificate or image changed).
    Returns: "running" (active and no restart asked; health not checked), "started" or "restarted".
    Fails:   CalledProcessError from `systemctl enable/start/restart`; SetupError when the container is not healthy
             within 900 s (last 40 log lines included).
    Feeds:   start_services.run, setup_openbao.run, images.switch_image."""
    subprocess.run(["systemctl", "enable", unit], check=True, capture_output=True)
    _settled(unit)
    active = subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0
    if active and not restart:
        return "running"
    # a unit that kept failing (a bad image restarted until systemd's start limit) refuses a start until its failed
    # state is cleared, and one still in its automatic-restart loop races a start: it is stopped first, which cancels
    # the pending restart (the rollback after a failed image update hit both now and then: manual 2.3.6.1.27, 2.3.6.2.9)
    if not active:
        subprocess.run(["systemctl", "stop", unit], capture_output=True)
    subprocess.run(["systemctl", "reset-failed", unit], capture_output=True)
    subprocess.run(["systemctl", "restart" if active else "start", unit], check=True)
    healthy, why = wait_healthy(container, timeout=900)
    if not healthy:
        logs = subprocess.run(["docker", "logs", "--tail", "40", container], capture_output=True, text=True)
        raise SetupError(f"{container} did not become healthy ({why}):\n{logs.stdout}{logs.stderr}")
    return "restarted" if active else "started"
