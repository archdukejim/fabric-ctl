import json
import os

from fabriclib.common.paths import INSTALL_DIR
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets

SORTED = os.path.join(INSTALL_DIR, "config", "machines-sorted.json")   # the machines moved before: never moved again


def sort_machines(v, actor="fabric", source="timer", secrets=None, container="samba", record=SORTED):
    """Purpose: move the Windows machines that joined themselves into the site's OU=machines into OU=windows, each
             once (manual 1.6.11.5, 2.1.6.36): the DC moves them, this records which, so a machine an admin moves
             back is never moved again.
    Inputs:  v — fabric vars (site_name); actor, source — for the audit; secrets — fabric's secrets (default:
             load_secrets()); container — the DC's container; record — the file of machines moved before.
    Returns: list of the machines' names moved now.
    Fails:   ValidationError from run_op (the directory unreachable or refusing); OSError writing the record.
    Feeds:   samba/run_domain_command (`fabricctl domain sort-machines`, the fabric-machines timer).
    Notes:   audited as MACHINE_SORT, one entry per machine."""
    try:
        with open(record) as f:
            done = json.load(f)
    except (OSError, ValueError):
        done = []
    moved = run_op(v, secrets if secrets is not None else load_secrets(), "sort_windows_machines",
                   {"skip": done}, container)
    if moved:
        os.makedirs(os.path.dirname(record), exist_ok=True)
        tmp = record + ".tmp"
        with open(tmp, "w") as f:
            json.dump(sorted(set(done) | {m["guid"] for m in moved}), f)
        os.replace(tmp, record)
    for m in moved:
        write_audit(actor, "MACHINE_SORT", f"machine={m['name']} to={m['to']}", source)
    return [m["name"] for m in moved]
