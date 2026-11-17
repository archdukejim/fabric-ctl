import subprocess
import time

# a unit between states: systemd is starting or stopping it (its own restart of a dependent among them)
MOVING = ("activating", "deactivating", "reloading")


def _unit_state(unit):
    """Purpose: a unit's ActiveState and SubState as systemd reports them.
    Inputs:  unit — systemd unit name.
    Returns: (active state, sub state), e.g. ("activating", "start-post"); ("", "") when systemctl answers nothing.
    Fails:   never (systemctl's own failure reads as ("", "")).
    Feeds:   unit_settled."""
    out = subprocess.run(["systemctl", "show", "-p", "ActiveState", "-p", "SubState", unit],
                         capture_output=True, text=True).stdout or ""
    vals = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return vals.get("ActiveState", ""), vals.get("SubState", "")


def unit_settled(unit, timeout=660, pause=2.0):
    """Purpose: wait while systemd is starting or stopping a unit, so a start of fabric's never interrupts one that
             is under way (2.3.2.5: restarting Postgres makes systemd restart Keycloak, which Requires it; a stop
             sent to Keycloak mid-start raced its container's removal and failed the start), and a start cut short
             from outside is judged by where the unit ends (2.3.1.57). A unit waiting in its automatic-restart loop is
             not waited for: it is in a loop, not on its way.
    Inputs:  unit — systemd unit name; timeout — seconds (a fabric unit's start allows 600, its health check after);
             pause — seconds between looks.
    Returns: (active state, sub state) once it no longer moves, or as it is at the timeout.
    Fails:   never.
    Feeds:   setup/start_unit, common/systemctl_up."""
    deadline = time.monotonic() + timeout
    while True:
        state, sub = _unit_state(unit)
        if state not in MOVING or sub == "auto-restart" or time.monotonic() >= deadline:
            return state, sub
        time.sleep(pause)
