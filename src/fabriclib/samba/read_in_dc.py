import json
import subprocess

from fabriclib.directory import held_op


def read_in_dc(container, script, timeout=60):
    """Purpose: one of the DC's read scripts (read_site_tree, read_sites, read_replication, read_dc_names), which read
             its own database as the system: in fabric-agent through a held process (2.1.8.35), otherwise by a `docker
             exec` of its own.
    Inputs:  container — the DC's container; script — the script's name, no suffix; timeout — seconds.
    Returns: the JSON object it gives.
    Fails:   ValueError saying why when it does not answer; subprocess.TimeoutExpired; OSError without docker.
    Feeds:   site_tree_records, domain_sites, replication_status, domain_dc_names."""
    if held_op.enabled():
        answer = held_op.send(container, {"local": script}, timeout)
        if "error" in answer:
            raise ValueError(answer["error"])
        return answer["result"]
    res = subprocess.run(["docker", "exec", "-e", "PYTHONDONTWRITEBYTECODE=1", container, "python3",
                          f"/fabric/{script}.py"], capture_output=True, text=True, timeout=timeout)
    if res.returncode != 0:
        raise ValueError((res.stderr.strip().splitlines() or ["no answer"])[-1])
    return json.loads(res.stdout)
