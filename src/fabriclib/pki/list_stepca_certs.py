import json
import os
import shutil
import subprocess
import tempfile

from fabriclib.common.errors import ValidationError
from fabriclib.common.one_off_labels import one_off_labels

READER = "/usr/local/bin/fabric-certlist"     # built into fabric's Step-CA image (packaging/images/stepca/reader/)
CONTAINER = "step-ca"
MEMORY = "256m"                               # its own limit: never Step-CA's 128 MB floor (plan_memory)


def _image(run, container):
    """Purpose: the image the Step-CA container runs (fabric's published one or this host's own build), so the reader
             is the one built with this Step-CA's database library.
    Inputs:  run — subprocess.run (tests replace it); container — Step-CA's container name.
    Returns: the image id (str).
    Fails:   ValidationError when there is no Step-CA container (Step-CA was never started here).
    Feeds:   list_stepca_certs."""
    res = run(["docker", "inspect", "-f", "{{.Image}}", container], capture_output=True, text=True)
    if res.returncode != 0 or not res.stdout.strip():
        raise ValidationError("Step-CA's container is not on this host: its certificates cannot be listed")
    return res.stdout.strip()


def list_stepca_certs(v, run=subprocess.run, container=CONTAINER):
    """Purpose: every certificate Step-CA signed, from its own database (decision 2.1.5.13, prototype 2.3.5.5): the
             database directory is copied (the live one is locked by step-ca, and is never written) and the copy is
             read by fabric-certlist in a throwaway container of the Step-CA image: no network, read-only, every
             capability dropped, as the step user. The copy is removed afterwards.
    Inputs:  v — settings: deploy_base_dir, service_users.step.uid / .gid; run — subprocess.run (tests); container —
             Step-CA's container, whose image is used (tests name their own).
    Returns: list of {"serial" (uppercase hex, no leading zeros), "subject", "cn", "issuer", "sans" (DNS names, IP
             addresses, e-mail addresses and URIs), "not_before", "not_after" (ISO 8601, UTC), "is_ca", "provisioner",
             "provisioner_type"} in the database's order; [] when Step-CA has no database yet.
    Fails:   ValidationError: no Step-CA container, or the reader failed (an image without it: built before 0.10.0),
             with its message; OSError copying the database.
    Feeds:   pki/list_certs."""
    data = os.path.join(v["deploy_base_dir"], "stepca", "data")
    db = os.path.join(data, "db")
    if not os.path.isdir(db):
        return []
    image = _image(run, container)
    uid, gid = (int(v["service_users"]["step"][k]) for k in ("uid", "gid"))
    work = tempfile.mkdtemp(prefix="fabric-certlist-")
    try:
        copy = os.path.join(work, "db")
        shutil.copytree(db, copy, ignore=shutil.ignore_patterns("LOCK"))
        for root, dirs, files in os.walk(work):
            for name in [root] + [os.path.join(root, n) for n in dirs + files]:
                os.chown(name, uid, gid)
        res = run(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges:true", "--memory", MEMORY, "--user", f"{uid}:{gid}",
                   "-v", f"{work}:/certlist", *one_off_labels(), "--entrypoint", READER, image, "/certlist/db"],
                  capture_output=True, text=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if res.returncode != 0:
        why = (res.stderr or res.stdout).strip()[-300:]
        if "executable file not found" in why or "no such file" in why.lower():
            why = "this Step-CA image has no certificate reader (an image built before 0.10.0: update it)"
        raise ValidationError(f"Step-CA's certificates cannot be read: {why}")
    out = []
    for line in res.stdout.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        sans = [*(row.get("dns") or []), *(row.get("ips") or []), *(row.get("emails") or []),
                *(row.get("uris") or [])]
        out.append({"serial": str(row.get("serial", "")).upper().lstrip("0") or "0", "subject": row.get("subject", ""),
                    "cn": row.get("cn", ""), "issuer": row.get("issuer", ""), "sans": sans,
                    "not_before": row.get("not_before", ""), "not_after": row.get("not_after", ""),
                    "is_ca": bool(row.get("is_ca")), "provisioner": row.get("provisioner", ""),
                    "provisioner_type": row.get("provisioner_type", "")})
    return out
