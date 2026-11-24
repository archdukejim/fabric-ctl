import re

from fabriclib.backup.install_backup_timer import install_backup_timer
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.paths import VARS_FILE
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit


def set_backup_schedule(actor, time=None, keep=None, public_key=None, off=False, source="cli", path=VARS_FILE,
                        install=install_backup_timer):
    """Purpose: the backup schedule (manual 1.3.7.5): its time, how many scheduled bundles are kept and its public key
             in vars.yaml, then its timer installed or removed to match; audited.
    Inputs:  actor, source — who (audit); time — "HH:MM" or None (unchanged; default 03:00); keep — int or None
             (unchanged; default 7); public_key — "age1…" or None (unchanged); off — True: the schedule off (its key
             removed, the other settings kept); path — vars.yaml; install — install_backup_timer (tests).
    Returns: {"schedule": "on HH:MM" or "off", "time", "keep", "public_key"}.
    Fails:   ValidationError: a time that is not HH:MM, keep below 1 or above 365, a public key that is not age1…, the
             schedule turned on with no public key; OSError writing vars.yaml or the units.
    Feeds:   run_backup_command (`backup schedule`), the agent's backup schedule route."""
    if time is not None and not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(time)):
        raise ValidationError(f"the time {time!r} is not HH:MM (24 hours)")
    if keep is not None and not (isinstance(keep, int) and 1 <= keep <= 365):
        raise ValidationError("keep is a number of scheduled backups from 1 to 365")
    if public_key is not None and not re.fullmatch(r"age1[0-9a-z]{58}", public_key):
        raise ValidationError("the public key is not an age public key (age1 and 58 more characters)")
    with vars_lock():
        v = load_vars(path)
        if time is not None:
            v["backup_schedule_time"] = time
        if keep is not None:
            v["backup_keep"] = keep
        if off:
            v["backup_public_key"] = None
        elif public_key is not None:
            v["backup_public_key"] = public_key
        elif not v.get("backup_public_key"):
            raise ValidationError("the schedule needs a public key: --public-key age1… (make one with age-keygen on "
                                  "another machine, and keep its private key there)")
        save_vars(v, path)
    state = install(v)
    write_audit(actor, "BACKUP_SCHEDULE", f"{state} keep={v.get('backup_keep') or 7}", source=source)
    return {"schedule": state, "time": v.get("backup_schedule_time") or "03:00", "keep": v.get("backup_keep") or 7,
            "public_key": v.get("backup_public_key")}
