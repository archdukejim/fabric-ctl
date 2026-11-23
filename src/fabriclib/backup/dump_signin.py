import os
import subprocess

from fabriclib.backup.postgres_login import postgres_login
from fabriclib.common.errors import ValidationError


def dump_signin(dest):
    """Purpose: Keycloak's database dumped while it runs (manual 1.3.7.4), `pg_dump -Fc` inside the postgres container
             over its local socket (the image trusts it), so no password is needed or passed; as the role
             postgres_login names.
    Inputs:  dest — the dump file to write (0600).
    Returns: its size in bytes.
    Fails:   ValidationError when pg_dump fails (Postgres down, the database missing); OSError writing dest.
    Feeds:   backup_plan (the signin section online)."""
    user, _ = postgres_login(subprocess.run)
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as out:
        res = subprocess.run(["docker", "exec", "postgres", "pg_dump", "-U", user, "-Fc", "keycloak"],
                             stdout=out, stderr=subprocess.PIPE, timeout=1800)
    if res.returncode != 0:
        os.remove(dest)
        raise ValidationError(f"Keycloak's database could not be dumped: {res.stderr.decode(errors='replace')[-300:]}")
    return os.path.getsize(dest)
