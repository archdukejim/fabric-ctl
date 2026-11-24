import contextlib

from fabriclib.common.errors import ValidationError
from fabriclib.dns.rndc import rndc


@contextlib.contextmanager
def freeze_zones():
    """Purpose: BIND's dynamic zones written to their files and held still while they are copied (manual 1.3.7.4:
             `rndc freeze`, then `rndc thaw`); updates wait meanwhile, and are thawed even when the copy fails.
    Inputs:  none (every zone of the bind9 container).
    Returns: a context manager.
    Fails:   ValidationError when the freeze fails or times out (nothing is copied).
    Feeds:   backup_plan (the dns section online)."""
    res = rndc(["freeze"], timeout=60)
    if res is None or res.returncode != 0:
        raise ValidationError("BIND's zones could not be frozen for the copy: "
                              f"{(res.stderr or res.stdout).strip() if res else 'rndc timed out'}")
    try:
        yield
    finally:
        rndc(["thaw"], timeout=60)
