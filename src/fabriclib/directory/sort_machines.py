import json
import os

from fabriclib.common.paths import INSTALL_DIR
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.constants import FABRIC_MANAGED
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets

SORTED = os.path.join(INSTALL_DIR, "config", "machines-sorted.json")   # what was done before: never done again


def sort_machines(v, actor="fabric", source="timer", secrets=None, container="samba", record=SORTED):
    """Purpose: the domain's machines placed, each once: a Windows machine that joined itself into OU=machines
             filed by its operatingSystem, a Server edition into OU=servers and `machines-servers`, any other into
             OU=desktops and `machines-desktops` (manual 1.6.13.3); a Linux machine of this site joined with an
             admin's password made a member of `fabric-managed` unless its join said unmanaged (1.6.11.6, 2.1.6.40).
             The DC does both; this records which machines, so one an admin moves back or takes out is left so.
    Inputs:  v — fabric vars (site_name); actor, source — for the audit; secrets — fabric's secrets (default:
             load_secrets()); container — the DC's container; record — the file of what was done before
             ({"sorted": [guid], "adopted": [guid]}).
    Returns: {"sorted": [names], "adopted": [names]}, what was done now.
    Fails:   ValidationError from run_op (the directory unreachable or refusing); OSError writing the record.
    Feeds:   samba/run_domain_command (`fabricctl domain sort-machines`, the fabric-machines timer).
    Notes:   audited as MACHINE_SORT and MACHINE_ADOPT, one entry per machine."""
    try:
        with open(record) as f:
            done = json.load(f)
    except (OSError, ValueError):
        done = {}
    done = {"sorted": list(done.get("sorted") or []), "adopted": list(done.get("adopted") or [])}
    secrets = secrets if secrets is not None else load_secrets()
    moved = run_op(v, secrets, "sort_windows_machines", {"skip": done["sorted"]}, container)
    adopted = run_op(v, secrets, "adopt_linux_machines", {"skip": done["adopted"]}, container)
    if moved or adopted:
        done["sorted"] = sorted(set(done["sorted"]) | {m["guid"] for m in moved})
        done["adopted"] = sorted(set(done["adopted"]) | {m["guid"] for m in adopted})
        os.makedirs(os.path.dirname(record), exist_ok=True)
        tmp = record + ".tmp"
        with open(tmp, "w") as f:
            json.dump(done, f)
        os.replace(tmp, record)
    for m in moved:
        write_audit(actor, "MACHINE_SORT", f"machine={m['name']} to={m['to']} type={m['type']}", source)
    for m in adopted:
        write_audit(actor, "MACHINE_ADOPT", f"machine={m['name']} group={FABRIC_MANAGED}", source)
    return {"sorted": [m["name"] for m in moved], "adopted": [m["name"] for m in adopted]}
