import subprocess

from fabriclib.common.unit_settled import unit_settled


def systemctl_up(units, restart=False, enable=False, timeout=None, capture=False):
    """Purpose: start (or restart) systemd units so that a start cut short from outside does not fail the caller:
             systemd re-executing mid-start, as unattended-upgrades makes it when it upgrades a library systemd links,
             kills the start's control process and systemd starts the unit again itself (the 0.10.0 rehearsal's bind9,
             twice, 2.3.1.57). A failed start is waited for; units that end active are up, the others are cleared and
             started once more, an error only if that fails too.
    Inputs:  units — list of unit names; restart — `restart` rather than `start`; enable — `systemctl enable` first
             (its own failure is an error at once); timeout — seconds for each systemctl call (None: no limit);
             capture — capture systemctl's output instead of letting it through.
    Returns: None once every unit is active (or systemctl said it started them).
    Fails:   CalledProcessError from `systemctl enable`, or from the second start; TimeoutExpired past timeout.
    Feeds:   setup/start_unit, setup/start_bootstrap, setup/start_services, setup/configure_firewall,
             setup/configure_network, setup/harden_docker, setup/join_host_domain, deploy/restart_changed,
             ntp/deploy_chrony, pki/pick_up_cert, federation/reparent_site, vault/run_vault_command (restart_openbao),
             undo/undo_runtime."""
    if enable:
        subprocess.run(["systemctl", "enable", *units], check=True, capture_output=capture, timeout=timeout)
    if subprocess.run(["systemctl", "restart" if restart else "start", *units], capture_output=capture,
                      timeout=timeout).returncode == 0:
        return
    down = [u for u in units if unit_settled(u)[0] != "active"]
    if not down:
        return                                      # systemd brought them up itself
    subprocess.run(["systemctl", "reset-failed", *down], capture_output=True)
    subprocess.run(["systemctl", "start", *down], check=True, capture_output=capture, timeout=timeout)
