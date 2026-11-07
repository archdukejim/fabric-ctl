import datetime
import os
import shutil

from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.sizing.advice import sizing_alerts
from fabriclib.sizing.state import RESULT, save_state
from fabriclib.system.memory_limit_mb import memory_limit_mb


def host_resources(v):
    """Purpose: what the host has, for the model (manual 1.8.8.8); what it cannot say is None, so no alert guesses.
    Inputs:  v — rendered vars (deploy_base_dir; what memory_limit_mb reads).
    Returns: {"ram" (MiB), "cores", "disk" (MiB free on fabric's data volume), "dc_memory" (MiB, the DC's limit)}.
    Fails:   never.
    Feeds:   refresh_sizing."""
    try:
        with open("/proc/meminfo") as f:
            ram = next(int(line.split()[1]) // 1024 for line in f if line.startswith("MemTotal:"))
    except (OSError, StopIteration, ValueError):
        ram = None
    try:
        disk = shutil.disk_usage(v["deploy_base_dir"]).free // (1024 * 1024)
    except OSError:
        disk = None
    return {"ram": ram, "cores": os.cpu_count(), "disk": disk, "dc_memory": memory_limit_mb(v, "samba")}


def refresh_sizing(v, config_dir, secrets=None, container="samba", now=None):
    """Purpose: the timer's work (fabric-sizing.timer, never a page's request, 1.8.8.2; decision 2.1.8.36): the
             install's
             size from the DC, what the host has, the alerts, written for the console and the host's commands.
    Inputs:  v — rendered vars; config_dir — fabric's config directory; secrets — fabric's secrets (default:
             load_secrets()); container — the DC's container; now — the time, for tests.
    Returns: the result written: {"at", "size", "host", "alerts"}.
    Fails:   ValidationError from run_op (the DC not reachable: the last result is kept); OSError writing.
    Feeds:   sizing/run_sizing_command."""
    size = run_op(v, secrets if secrets is not None else load_secrets(), "directory_size", {}, container)
    host = host_resources(v)
    at = (now or datetime.datetime.now(datetime.timezone.utc)).isoformat(timespec="seconds")
    out = {"at": at, "size": size, "host": host, "alerts": sizing_alerts(size, host)}
    save_state(os.path.join(config_dir, RESULT), out)
    return out
