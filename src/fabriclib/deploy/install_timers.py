import os
import subprocess

from fabriclib.common.copy_if_changed import copy_if_changed

# fabric's scheduled jobs (`services` consent): 2.1.5.4, 2.1.7.4, 1.6.11.5, 1.6.11.11, 1.6.13.4, 2.1.7.17
TIMERS = ["fabric-certs", "fabric-db-rotate", "fabric-machines", "fabric-host-managed", "fabric-grants",
          "fabric-local-admin"]
# timers of an optional part: installed while all its flags are on, removed when one is off
OPTIONAL = {"fabric-dns-lists": ("install_resolver",),                    # the lists, daily (manual 1.12.2.10)
            "fabric-dns-log": ("install_resolver", "install_keycloak"),  # the query log, 5 min (1.12.2.13)
            "fabric-dhcp-names": ("install_kea",),    # DHCP names left behind, hourly (1.10.4.20, 2.1.10.22)
            "fabric-plan-watch": ("install_kea",)}    # the plan poll, every 30 s (1.10.4.26, 2.1.10.24)


def install_timers(paths, v=None):
    """Purpose: install fabric's timers and their services and keep them enabled; an optional part's timer only
             while every part it needs is on (removed when one is turned off).
    Inputs:  paths — deploy_paths() (jinja: the templates folder); v — rendered vars (the install_* flags of
             OPTIONAL); None: the optional timers are left as they are.
    Returns: True if a unit file changed (systemd reloaded here).
    Fails:   OSError copying or removing the files; systemctl failures are not raised (a host without systemd running,
             such as a render test, keeps the files).
    Feeds:   apply_deployment."""
    on = list(TIMERS)
    off = []
    if v is not None:
        for name, flags in OPTIONAL.items():
            (on if all(v.get(f) for f in flags) else off).append(name)
    changed = False
    for name in on:
        for kind in ("service", "timer"):
            changed |= bool(copy_if_changed(os.path.join(paths["jinja"], "systemd", f"{name}.{kind}"),
                                            f"/etc/systemd/system/{name}.{kind}", 0o644))
    for name in off:
        if os.path.exists(f"/etc/systemd/system/{name}.timer"):
            subprocess.run(["systemctl", "disable", "--now", f"{name}.timer"], capture_output=True)
        for kind in ("service", "timer"):
            path = f"/etc/systemd/system/{name}.{kind}"
            if os.path.exists(path):
                os.remove(path)
                changed = True
    if changed:
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    for name in on:
        subprocess.run(["systemctl", "enable", "--now", f"{name}.timer"], capture_output=True)
    return changed
