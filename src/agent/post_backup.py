import os

from agent.backup_file import backup_file
from agent.get_backup import site_name
from agent.job_store import JOBS
from agent.read_text import read_text
from agent.require_domain_admin import require_domain_admin
from fabriclib.backup.backup_running import backup_running
from fabriclib.backup.is_domain_admin import is_domain_admin
from fabriclib.backup.make_backup import make_backup
from fabriclib.backup.read_backup_key import MIN_PASSPHRASE
from fabriclib.backup.read_build import read_build
from fabriclib.backup.restore_section import restore_section
from fabriclib.backup.sections import SECTIONS
from fabriclib.backup.set_backup_schedule import set_backup_schedule
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.paths import SECRETS_FILE
from fabriclib.common.write_audit import write_audit
from agent.route_not_found import RouteNotFound


def _running():
    """Purpose: a refusal while a backup or restore holds its lock (manual 1.3.7.4), before a job is started.
    Inputs:  none.
    Returns: None.
    Fails:   ValidationError naming the run.
    Feeds:   post_backup."""
    pid = backup_running()
    if pid:
        raise ValidationError(f"a backup or restore is running (pid {pid}): wait for it, then try again")


def _make_key(v, data):
    """Purpose: how Back up now seals its bundle: the schedule's public key, or a passphrase of 12 characters or more.
    Inputs:  v — vars (backup_public_key); data — the body (scheduled_key, passphrase).
    Returns: {"passphrase", "public_key"}, one of them set.
    Fails:   ValidationError: no schedule's key, a passphrase too short.
    Feeds:   post_backup."""
    if data.get("scheduled_key") is True:
        if not v.get("backup_public_key"):
            raise ValidationError("no schedule's public key is set: set the schedule, or give a passphrase")
        return {"passphrase": None, "public_key": v["backup_public_key"]}
    passphrase = data.get("passphrase")
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE:
        raise ValidationError(f"a passphrase of {MIN_PASSPHRASE} characters or more: nothing was made")
    return {"passphrase": passphrase, "public_key": None}


def _open_key(data):
    """Purpose: what opens the bundle being restored: its passphrase, or the schedule's private key.
    Inputs:  data — the body (key).
    Returns: {"passphrase", "private_key"}, one of them set.
    Fails:   ValidationError for no key.
    Feeds:   post_backup."""
    key = data.get("key")
    if not isinstance(key, str) or not key.strip():
        raise ValidationError("key: the bundle's passphrase, or the schedule's private key (AGE-SECRET-KEY-1…)")
    if key.strip().startswith("AGE-SECRET-KEY-1"):
        return {"passphrase": None, "private_key": key.strip()}
    return {"passphrase": key, "private_key": None}


def post_backup(route, actor, data, caller, load=load_vars, allowed=is_domain_admin, jobs=JOBS, audit=write_audit,
                make=make_backup, restore=restore_section, schedule=set_backup_schedule):
    """Purpose: the console's Backups page changes (manual 1.3.7.9, 1.3.3.1): POST /v1/backup/now (a job), /schedule,
             /restore (one section, a job). A Domain Admin only (1.3.7.12), checked first; the key never leaves this
             process's memory and is never in a job's result.
    Inputs:  route — ["backup", "now"|"schedule"|"restore"]; actor — the audit's user; data — the body: now
             (passphrase, or scheduled_key true), schedule (time, keep, public_key, or off true), restore (file,
             section, key, confirm: the site's name typed); caller — the token's user (None: a root peer); load,
             allowed, jobs, audit, make, restore, schedule — the functions used (tests give their own).
    Returns: now, restore: {"id"} of the job (its result {"message"}); schedule: set_backup_schedule's result.
    Fails:   ValidationError (-> 400): not a Domain Admin, a backup or restore running, a bad key, a section restored
             alone that may not be (secrets) or that is unknown, the site's name not typed, the schedule's refusals;
             NotFound for a bundle that is not there; RouteNotFound for another route.
    Feeds:   agent/post_route."""
    v = load()
    require_domain_admin(v, caller, allowed)
    owner = actor if caller is not None else None
    base = v["deploy_base_dir"]
    if route == ["backup", "schedule"]:
        keep = data.get("keep")
        try:
            keep = None if keep in (None, "") else int(keep)
        except (TypeError, ValueError):
            raise ValidationError("keep: a number from 1 to 365") from None
        return schedule(actor, time=read_text(data, "time") or None, keep=keep,
                        public_key=read_text(data, "public_key") or None, off=data.get("off") is True, source="web")
    if route == ["backup", "now"]:
        key = _make_key(v, data)
        _running()
        audit(actor, "BACKUP_START", "kind=manual method=online", source="web")

        def made():
            path = make(base, v, SECRETS_FILE, "manual", "online", actor=actor, source="web", **key)
            return {"message": f"Bundle made: {os.path.basename(path)}."}
        return jobs.start("backup", owner, made)
    if route == ["backup", "restore"]:
        path, section = backup_file(data.get("file")), read_text(data, "section")
        if section not in SECTIONS:
            raise ValidationError(f"section: one of {', '.join(SECTIONS)}")
        if SECTIONS[section].get("alone") is False:
            raise ValidationError(f"{section} is restored only with the whole bundle (manual 1.3.7.8)")
        if read_text(data, "confirm") != site_name(v):
            raise ValidationError(f"type the site's name ({site_name(v)}) to restore {section}: nothing changed")
        key = _open_key(data)
        _running()
        version = read_build(os.path.join(base, "fabric"))["version"]
        config = os.path.join(base, "fabric", "config")
        audit(actor, "RESTORE_SECTION_START", f"bundle={os.path.basename(path)} section={section}", source="web")

        def restored():
            out = restore(base, config, path, section, key, version, actor=actor, source="web")
            return {"message": f"{section} restored from {os.path.basename(path)}. The state it replaced is in "
                               f"{os.path.basename(out['safety'])}."}
        return jobs.start("restore", owner, restored)
    raise RouteNotFound()
