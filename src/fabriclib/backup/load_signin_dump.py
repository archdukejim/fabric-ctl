import os
import subprocess

from fabriclib.backup.postgres_login import postgres_login
from fabriclib.backup.restore_pending import read_restore_pending, write_restore_pending
from fabriclib.common.errors import ValidationError


def load_signin_dump(config_dir):
    """Purpose: once Postgres runs after an online bundle's restore, and before Keycloak starts (manual 1.3.7.6):
             Keycloak's database loaded from its dump with pg_restore (--clean --if-exists) over the container's own
             socket, as the role postgres_login names, its objects made as Keycloak's own role when that exists.
    Inputs:  config_dir — fabric's config folder.
    Returns: True when a dump was loaded, False when none was pending.
    Fails:   ValidationError when pg_restore fails (the dump stays pending); OSError reading it.
    Feeds:   setup/start_services (after the postgres unit starts)."""
    pending = read_restore_pending(config_dir)
    dump = pending.get("signin")
    if not dump:
        return False
    user, owner = postgres_login(subprocess.run)
    with open(dump, "rb") as f:
        res = subprocess.run(["docker", "exec", "-i", "postgres", "pg_restore", "-U", user, "-d", "keycloak",
                              "--clean", "--if-exists", "--no-owner", *([f"--role={owner}"] if owner else [])],
                             stdin=f, capture_output=True, timeout=1800)
    if res.returncode != 0:
        why = res.stderr.decode(errors="replace")[-300:]
        raise ValidationError(f"Keycloak's database could not be restored: {why}")
    pending.pop("signin")
    write_restore_pending(config_dir, pending)
    os.remove(dump)
    return True
