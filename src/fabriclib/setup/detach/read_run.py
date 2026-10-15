import os

import yaml

from fabriclib.setup.detach.constants import RECORD


def read_run(config_dir):
    """Purpose: the record of setup's last full run (manual 1.3.2.3.3): which steps finished, which one ran last,
             how it ended.
    Inputs:  config_dir — the install's config folder (<config_dir>/setup-run.yaml).
    Returns: the record (dict: id, state "running"/"done"/"failed", steps done, current, restart_services, options,
             result, handoff), or None when there is none or it does not parse as a mapping (a damaged record is
             treated as no record: setup then starts over, which is safe since its steps are idempotent).
    Fails:   OSError when the file exists but cannot be read.
    Feeds:   setup/run_setup (choose_start), detach/follow_run (the result), detach/run_worker, detach/hand_over."""
    path = os.path.join(config_dir, RECORD)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError:
            return None
    return data if isinstance(data, dict) and data.get("id") else None
