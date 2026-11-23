#!/usr/bin/env python3
"""The role a backup or a restore reaches Keycloak's database as (backup/postgres_login; manual 1.3.7.4, 1.3.7.6):
Postgres's own admin once setup has moved off the bootstrap role and locked it, its objects then made as Keycloak's own
role; the bootstrap role on a Postgres not moved yet. docker is stood in for (the real dump and load: the sandbox's
Back up now and whole restore, tests/sandbox/run.sh).

    python3 tests/backup/postgres_login_test.py
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.backup.postgres_login import postgres_login  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


asked = []


def runner(admin_ok):
    def run(cmd, **kw):
        asked.append(cmd)
        return subprocess.CompletedProcess(cmd, 0 if admin_ok else 2, "1\n" if admin_ok else "",
                                           "" if admin_ok else 'FATAL:  role "fabric_admin" does not exist')
    return run


check("Postgres moved to its own admin: log in as it, objects made as Keycloak's own role",
      postgres_login(runner(True)) == ("fabric_admin", "keycloak_db") and "-U" in asked[-1]
      and asked[-1][asked[-1].index("-U") + 1] == "fabric_admin" and "postgres" in asked[-1], asked)
check("negative: a Postgres not moved yet (no admin role): the bootstrap role, nothing set for objects",
      postgres_login(runner(False)) == ("keycloak", None))
check("no password anywhere in the probe (the container's socket is trusted)",
      not any("PGPASSWORD" in " ".join(c) or "password" in " ".join(c).lower() for c in asked), asked)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
