"""Names of setup's detached run (decision 2.1.2.26, manual 1.3.2.3)."""

UNIT = "fabric-setup.service"           # the transient unit setup's work runs as (systemd-run --collect)
RECORD = "setup-run.yaml"               # in the install's config folder: the run's progress (no secret)
LOG = "setup-run.log"                   # in the install's config folder: everything the run printed
HANDOFF_DIR = "/run/fabric-setup"       # tmpfs, root 0700: the secrets handed to the unit, one 0600 file per run
HANDOFF_SUFFIX = ".handoff"
# what `systemctl is-active` says while the unit's process may still run or write its log
RUNNING_STATES = ("active", "activating", "deactivating", "reloading", "refreshing")
# names only, never secrets: who ran sudo (their home gets ~/fabric-admin) and the SSH client (the firewall's
# lockout guard)
PASSED_ENV = ("SUDO_USER", "SSH_CONNECTION")
