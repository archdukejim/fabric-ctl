import os
import subprocess

SERVICES = ["nginx", "bind9", "stepca", "postgres", "keycloak", "openbao", "kea", "freeradius", "samba",
            "bind9-resolver", "adguard-filter", "fluentbit", "fabric-web", "fabric-agent", "fabric-federation",
            "chrony"]
# systemd unit -> its container (units without one run on the host)
CONTAINERS = {"nginx": "nginx", "bind9": "bind9", "stepca": "step-ca", "postgres": "postgres",
              "keycloak": "keycloak", "openbao": "openbao", "kea": "kea-dhcp4", "freeradius": "freeradius",
              "samba": "samba", "fluentbit": "fluentbit", "fabric-web": "fabric-web",
              "bind9-resolver": "bind9-resolver", "adguard-filter": "adguard-filter"}


def _health(containers):
    """Purpose: containers' Docker health status, in one call.
    Inputs:  containers — names.
    Returns: {name: "healthy", "unhealthy" or "starting"; "no container" for a missing container or one with no
             healthcheck; "timeout" after 5 s}.
    Fails:   FileNotFoundError without docker.
    Feeds:   service_status."""
    try:
        res = subprocess.run(["docker", "inspect", "-f",
                              "{{.Name}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", *containers],
                             capture_output=True, text=True, timeout=5)
    except subprocess.TimeoutExpired:
        return dict.fromkeys(containers, "timeout")
    seen = dict((ln.split() + [""])[:2] for ln in res.stdout.splitlines() if ln.strip())
    return {c: seen.get(f"/{c}") or "no container" for c in containers}


def _active(services):
    """Purpose: services' systemd states, in one call.
    Inputs:  services — unit names.
    Returns: {name: its state, "unknown" when none is printed, "timeout" after 5 s}.
    Fails:   FileNotFoundError without systemctl.
    Feeds:   service_status."""
    try:
        res = subprocess.run(["systemctl", "is-active", *services], capture_output=True, text=True, timeout=5)
    except subprocess.TimeoutExpired:
        return dict.fromkeys(services, "timeout")
    lines = res.stdout.splitlines()
    return {s: (lines[i].strip() if i < len(lines) else "") or "unknown" for i, s in enumerate(services)}


def service_status():
    """Purpose: every fabric service installed on this host with its systemd state and container health.
    Inputs:  none (SERVICES, CONTAINERS; systemctl is-active; /etc/systemd/system/<svc>.service).
    Returns: [(service, systemd state or "timeout", container health)]; health is "" for host services
             (fabric-agent). An inactive service without a unit file is left out.
    Fails:   FileNotFoundError without systemctl/docker; timeouts are reported as "timeout", not raised.
    Feeds:   control_stack (status, and the unit list for stop); fabric-agent (agent/ (fabric-agent)) for the web UI."""
    states, health = _active(SERVICES), _health(list(CONTAINERS.values()))
    result = []
    for svc in SERVICES:
        state = states[svc]
        if state != "inactive" or os.path.exists(f"/etc/systemd/system/{svc}.service"):
            result.append((svc, state, health[CONTAINERS[svc]] if svc in CONTAINERS else ""))
    return result
