import subprocess

# sssd's socket units (sssd-nss.socket, -pam, -pam-priv, -sudo, -pac, -autofs, -ssh; enabled by default on Ubuntu
# 24.04 and Debian 12): a second way to start the responders `services = nss, pam, sudo` already starts, refused
# for one services names, so they fail at every boot (manual 1.6.7.8, 2.1.6.95). The Linux join
# (templates/nginx/www/certs/join-linux.sh.j2) lists the same glob and disables and masks them the same way;
# tests/setup/common/sssd_sockets_test.py fails if the two drift.
GLOB = "sssd-*.socket"


def socket_units(run=subprocess.run):
    """Purpose: the sssd socket units installed on this host (masked ones included).
    Inputs:  run — subprocess.run (tests).
    Returns: list of str (unit names), [] without systemd or sssd.
    Fails:   never (a missing systemctl is no units).
    Feeds:   socket_states, mask_sockets, restore_sockets."""
    try:
        out = run(["systemctl", "list-unit-files", GLOB, "--no-legend"], capture_output=True, text=True).stdout
    except (OSError, AttributeError):
        return []
    return sorted({line.split()[0] for line in (out or "").splitlines() if line.split()})


def socket_states(run=subprocess.run):
    """Purpose: how each sssd socket unit is set now (`systemctl is-enabled`), kept before fabric changes them so the
             undo puts them back (2.1.6.95).
    Inputs:  run — subprocess.run (tests).
    Returns: {unit: state} (e.g. "enabled", "disabled", "masked"); {} with none installed.
    Fails:   never.
    Feeds:   setup/join_host_domain (into member.json)."""
    return {u: (run(["systemctl", "is-enabled", u], capture_output=True, text=True).stdout or "").strip() or "unknown"
            for u in socket_units(run)}


def sockets_masked(run=subprocess.run):
    """Purpose: whether every installed sssd socket unit is masked (nothing to change).
    Inputs:  run — subprocess.run (tests).
    Returns: bool (True with none installed).
    Fails:   never.
    Feeds:   setup/join_host_domain."""
    return all(s == "masked" for s in socket_states(run).values())


def mask_sockets(run=subprocess.run):
    """Purpose: disable, stop and mask every sssd socket unit, and clear what systemd keeps of their failures, so
             sssd alone starts its responders (as join-linux.sh does, 1.6.7.8; masked: a package upgrade does not
             enable them again).
    Inputs:  run — subprocess.run (tests).
    Returns: list of str, the units masked ([] with none).
    Fails:   never; systemctl failures are ignored (a host without systemd running).
    Feeds:   setup/join_host_domain."""
    units = socket_units(run)
    if units:
        run(["systemctl", "disable", "--now", *units], capture_output=True)
        run(["systemctl", "mask", *units], capture_output=True)
        run(["systemctl", "reset-failed", *units], capture_output=True)
    return units


def restore_sockets(before, run=subprocess.run):
    """Purpose: put the sssd socket units back as they were before fabric masked them (2.1.6.95): each unmasked, then
             enabled, disabled or masked as recorded; one not recorded (its package came with fabric, or an install
             made before 0.8.0 kept no record) back to its package's default (`systemctl preset`). Their failures are
             cleared, so an uninstall leaves no failed sssd unit. Not started: they start at the next boot (or
             sockets.target) as the packages would.
    Inputs:  before — {unit: state} from socket_states, or None; run — subprocess.run (tests).
    Returns: list of str: one line naming each unit and how it was put back; [] with none installed.
    Fails:   never; systemctl failures are ignored.
    Feeds:   undo/undo_member."""
    before = before or {}
    done = []
    for unit in socket_units(run):
        state = before.get(unit)
        run(["systemctl", "unmask", unit], capture_output=True)
        if state is None:
            run(["systemctl", "preset", unit], capture_output=True)
            how = "its package's default"
        elif state == "masked":
            run(["systemctl", "mask", unit], capture_output=True)
            how = "masked"
        elif state.startswith("enabled"):
            run(["systemctl", "enable", unit], capture_output=True)
            how = "enabled"
        else:
            run(["systemctl", "disable", unit], capture_output=True)
            how = "disabled"
        run(["systemctl", "reset-failed", unit], capture_output=True)
        done.append(f"{unit} {how}")
    return [f"sssd's socket units as before fabric: {', '.join(done)}"] if done else []
