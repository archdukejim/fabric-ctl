import os
import shutil
import time

from fabriclib.backup.backup_lock import backup_lock
from fabriclib.backup.backup_plan import DUMPS, backup_plan
from fabriclib.backup.check_backup_space import check_backup_space
from fabriclib.backup.make_bundle import FOLDER, make_bundle
from fabriclib.backup.read_build import read_build
from fabriclib.backup.section_paths import section_paths
from fabriclib.backup.sections import ORDER
from fabriclib.common.console import info, ok
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.secrets.export_secrets import export_secrets
from fabriclib.secrets.secrets_in_openbao import secrets_in_openbao
from fabriclib.setup.stop_for_copy import stop_for_copy

PACKAGED = "/usr/lib/fabricctl/fabric"


def _meta(base, v, method):
    """Purpose: the manifest's description of the install (manual 1.3.7.2).
    Inputs:  base — install root; v — vars; method — "cold" or "online".
    Returns: dict: fabric_version and commit (the install's BUILD, else the package's), domain, host_ip, lan_cidr,
             lan_gateway, base, method.
    Fails:   never (an unknown version is "?").
    Feeds:   make_backup."""
    build = read_build(base)
    if build["version"] == "?":
        build = read_build(PACKAGED)
    return {"fabric_version": build["version"], "commit": build["commit"],
            "domain": v.get("domain"), "host_ip": v.get("host_ip"), "lan_cidr": v.get("lan_cidr"),
            "lan_gateway": v.get("lan_gateway"), "base": base, "method": method}


def make_backup(base, v, secrets_file, kind, method, passphrase=None, public_key=None, actor="root", source="cli",
                folder=FOLDER, only=None):
    """Purpose: make one bundle of the install (manual 1.3.7.4): online while fabric runs (by hand, scheduled), or
             cold (uninstall, reinstall: fabric's secrets read out of OpenBao into RAM, then fabric stopped and proven
             stopped). One at a time, with room for it checked first, and audited either way.
    Inputs:  base — install root; v — vars.yaml dict; secrets_file — fabric-secrets.yml's path; kind — bundle kind;
             method — "online" or "cold"; passphrase / public_key — exactly one (make_bundle); actor, source — who
             (audit); folder — the backups folder; only — the sections to pack (the others empty), or None for all.
    Returns: the bundle's path. Cold: fabric is left stopped (the uninstall that follows removes it).
    Fails:   ValidationError: another backup or restore running, too little disk, a dump or the stop failing, age;
             audited as BACKUP_FAILED, and nothing is left behind (RAM dumps removed, no partial bundle).
    Feeds:   run_backup_command, fabric-backup.service, the agent's backup route, run_uninstall_command,
             run_reinstall_command."""
    started = time.time()
    try:
        with backup_lock("a backup"):
            paths = [p for s in ORDER if only is None or s in only for p, _ in section_paths(s, base, v)]
            check_backup_space(folder, paths)
            shutil.rmtree(DUMPS, ignore_errors=True)
            os.makedirs(DUMPS, mode=0o700)
            try:
                if method == "cold":
                    if secrets_in_openbao(secrets_file):
                        export_secrets(secrets_file, os.path.join(DUMPS, "secrets", "fabric-secrets.yml"))
                    info("stopping fabric for a consistent copy")
                    stop_for_copy(base)
                plan = backup_plan(base, v, method, only=only)
                if method == "cold" and os.path.isdir(os.path.join(DUMPS, "secrets")):
                    plan = [(s, p, os.path.join(DUMPS, "secrets") if s == "secrets" else x, a) for s, p, x, a in plan]
                path = make_bundle(plan, v.get("hostname") or "fabric", _meta(base, v, method), kind,
                                   passphrase=passphrase, public_key=public_key, folder=folder)
            finally:
                shutil.rmtree(DUMPS, ignore_errors=True)
    except ValidationError as exc:
        write_audit(actor, "BACKUP_FAILED", f"kind={kind} method={method}: {exc}", source=source)
        raise
    size = os.path.getsize(path)
    write_audit(actor, "BACKUP_MADE", f"kind={kind} method={method} file={os.path.basename(path)} size={size} "
                f"seconds={int(time.time() - started)}", source=source)
    ok(f"backup written: {path} ({size // 2**20} MiB, root only)")
    return path
