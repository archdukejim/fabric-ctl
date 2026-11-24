import os

from agent.backup_file import backup_file
from agent.bundle_checks import CHECKS
from agent.file_answer import FileAnswer
from agent.require_domain_admin import require_domain_admin
from fabriclib.backup.backup_running import backup_running
from fabriclib.backup.console_restore_running import LOG, console_restore_running
from fabriclib.backup.is_domain_admin import is_domain_admin
from fabriclib.backup.list_bundles import list_bundles
from fabriclib.backup.read_build import read_build
from fabriclib.backup.schedule_status import schedule_status
from fabriclib.backup.sections import ORDER, SECTIONS
from fabriclib.common.load_vars import load_vars
from fabriclib.common.write_audit import write_audit
from agent.route_not_found import RouteNotFound


def site_name(v):
    """Purpose: the name typed to confirm a restore, as the CLI asks it (manual 1.3.7.8).
    Inputs:  v — vars.
    Returns: str.
    Fails:   never.
    Feeds:   get_backup, agent/post_backup."""
    return str(v.get("site_name") or v.get("hostname") or "fabric")


def _console_restore(log=LOG):
    """Purpose: the console's whole restore as the page shows it once the console is back (manual 1.3.7.9): whether
             it runs, and the end of its log.
    Inputs:  log — its log.
    Returns: {"running": bool, "tail": the last 20 lines ("" with no log)}.
    Fails:   never.
    Feeds:   get_backup."""
    try:
        with open(log, errors="replace") as f:
            tail = "".join(f.readlines()[-20:])
    except OSError:
        tail = ""
    return {"running": console_restore_running(), "tail": tail}


def get_backup(route, user, load=load_vars, checks=CHECKS, audit=write_audit, allowed=is_domain_admin):
    """Purpose: the console's Backups page reads (manual 1.3.7.9, 1.3.3.1): GET /v1/backup/allowed, /v1/backup and
             /v1/backup/bundles/<file>. Every one but allowed needs a Domain Admin (1.3.7.12), checked first.
    Inputs:  route — ["backup", ...]; user — the token's user (None: a root peer); load, checks, audit, allowed —
             load_vars, CHECKS, write_audit, is_domain_admin (tests give their own).
    Returns: allowed: {"allowed"}; backup: {"bundles": list_bundles' rows each with check, opened_by and method;
             "schedule": schedule_status; "running": whether a backup or restore runs; "console_restore":
             {"running", "tail"}; "site"; "version": the installed fabric's; "sections": [{"name", "what",
             "depends", "alone"}]}; a bundle: FileAnswer (streamed by the handler), audited BACKUP_DOWNLOAD.
    Fails:   ValidationError: not a Domain Admin, a name that is not a bundle's, the DC not answering; NotFound for a
             bundle that is not there; RouteNotFound for another route.
    Feeds:   agent/get_route."""
    v = load()
    if route == ["backup", "allowed"]:
        return {"allowed": bool(allowed(v, user))}
    require_domain_admin(v, user, allowed)
    if route == ["backup"]:
        rows = [dict(r, **(checks.of(r["path"]) if not r["error"] else
                           {"check": r["error"], "opened_by": "", "method": ""})) for r in list_bundles()]
        for r in rows:
            r.pop("path", None)               # the host's path stays on the host
        base = v["deploy_base_dir"]
        return {"bundles": rows, "schedule": schedule_status(v), "running": bool(backup_running()),
                "console_restore": _console_restore(),
                "site": site_name(v), "version": read_build(os.path.join(base, "fabric"))["version"],
                "sections": [{"name": n, "what": SECTIONS[n]["what"], "depends": SECTIONS[n]["depends"],
                              "alone": SECTIONS[n].get("alone", True)} for n in ORDER]}
    if len(route) == 3 and route[1] == "bundles":
        path = backup_file(route[2])
        audit(user or "root", "BACKUP_DOWNLOAD", f"file={route[2]} size={os.path.getsize(path)}", source="web")
        return FileAnswer(path, route[2])
    raise RouteNotFound()
