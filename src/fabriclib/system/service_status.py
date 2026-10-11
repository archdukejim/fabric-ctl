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


def _health(container):
    """Purpose: a container's Docker health status.
    Inputs:  container — name.
    Returns: "healthy", "unhealthy" or "starting"; "no container" when inspect prints nothing (missing
             container or no healthcheck); "timeout" after 5 s.
    Fails:   FileNotFoundError without docker.
    Feeds:   service_status."""
    try:
        res = subprocess.run(["docker", "inspect", "-f", "{{.State.Health.Status}}", container],
                             capture_output=True, text=True, timeout=5)
    except subprocess.TimeoutExpired:
        return "timeout"
    return res.stdout.strip() or "no container"


def service_status():
    """Purpose: every fabric service installed on this host with its systemd state and container health.
    Inputs:  none (SERVICES, CONTAINERS; systemctl is-active; /etc/systemd/system/<svc>.service).
    Returns: [(service, systemd state or "timeout", container health)]; health is "" for host services
             (fabric-agent). An inactive service without a unit file is left out.
    Fails:   FileNotFoundError without systemctl/docker; timeouts are reported as "timeout", not raised.
    Feeds:   control_stack (status, and the unit list for stop); fabric-agent (agent/ (fabric-agent)) for the web UI."""
    result = []
    for svc in SERVICES:
        try:
            res = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True, timeout=5)
            state = res.stdout.strip() or "unknown"
        except subprocess.TimeoutExpired:
            state = "timeout"
        if state != "inactive" or os.path.exists(f"/etc/systemd/system/{svc}.service"):
            result.append((svc, state, _health(CONTAINERS[svc]) if svc in CONTAINERS else ""))
    return result
