import subprocess

ADMIN = "fabric_admin"         # Postgres's own admin (setup/ensure_db_rotation.PG_ADMIN)
OWNER = "keycloak_db"          # Keycloak's own role, owning its database (vault/rotate_db_password.KC_ROLE)
BOOTSTRAP = "keycloak"         # the role Postgres was made with, locked once setup moves off it (ensure_db_rotation)


def postgres_login(run=subprocess.run):
    """Purpose: the role a backup or a restore reaches Keycloak's database as, over the postgres container's own socket
             (manual 1.3.7.4, 1.3.7.6): Postgres's own admin once setup has moved off the bootstrap role, which it then
             locks (found by the sandbox, 2026-11-23: "role keycloak is not permitted to log in"); the bootstrap
             role on a Postgres not moved yet (a fresh restore, before that step).
    Inputs:  run — subprocess.run (tests).
    Returns: (role to log in as, role objects are made by: OWNER when logged in as the admin, else None).
    Fails:   OSError without docker.
    Feeds:   dump_signin, load_signin_dump."""
    probe = run(["docker", "exec", "postgres", "psql", "-X", "-q", "-A", "-t", "-U", ADMIN, "-d", "keycloak", "-c",
                 "SELECT 1"], capture_output=True, text=True, timeout=60)
    if probe.returncode == 0:
        return ADMIN, OWNER
    return BOOTSTRAP, None
