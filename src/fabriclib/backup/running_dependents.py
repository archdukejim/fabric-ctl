import subprocess


def running_dependents(units, run=subprocess.run):
    """Purpose: the running services that depend on the units a section restore stops (manual 1.3.7.8): systemd stops
             them too (Kea's unit Requires= bind9, so a dns restore took DHCP down; found by the sandbox, 2026-11-23),
             and the restore must bring them back.
    Inputs:  units — the unit names to be stopped; run — subprocess.run (tests).
    Returns: list of unit names (without .service), running now, depending on any of units, not in units; in the
             order found, each once.
    Fails:   never for systemctl's own errors (a unit it does not know has no dependents); OSError without systemctl.
    Feeds:   restore_section."""
    found = []
    for unit in units:
        res = run(["systemctl", "list-dependencies", "--reverse", "--plain", "--no-legend", "--no-pager",
                   f"{unit}.service"], capture_output=True, text=True)
        for line in (res.stdout or "").splitlines()[1:]:          # the first line is the unit itself
            name = line.strip().lstrip("●○").strip()
            if not name.endswith(".service"):
                continue
            name = name[:-len(".service")]
            if name in units or name in found:
                continue
            if run(["systemctl", "is-active", "--quiet", name]).returncode == 0:
                found.append(name)
    return found
