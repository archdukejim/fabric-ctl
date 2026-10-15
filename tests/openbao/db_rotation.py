#!/usr/bin/env python3
"""Keycloak's database password rotated by OpenBao (decision 2.1.7.4, manual 1.7.1), against the real pinned Postgres
and OpenBao images on a private test network: Postgres with TLS answering as `postgres` (its alias, as on fabric_net),
OpenBao initialised and unsealed through its API. fabric's own configure_db_engine and rotate_db_password run against
them; re-rendering and restarting Keycloak is stood in for by a callable that records each call (the sandbox runs
the real one).

- the take-over: Postgres's own admin made, Keycloak moved to its own role (no superuser) owning its database and the
  tables made before, OpenBao's database engine and static role, the password rotated at once and saved; the role
  Postgres was created with (a superuser it cannot stop being) locked; the old password refused, the new one accepted
- converging again changes nothing; a rotation gives a new password, the previous one refused
- refused: a rotation OpenBao does not allow (the old password keeps working, the failure recorded); Keycloak not
  coming back (recorded, raised); OpenBao reaching Postgres by a name its certificate does not carry

    sudo python3 tests/openbao/db_rotation.py          (needs Docker, openssl, root)
"""
import datetime
import json
import os
import shutil
import subprocess
import sys
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.vault.rotate_db_password as rotate_mod  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.setup.ensure_db_rotation import configure_db_engine  # noqa: E402
from fabriclib.vault.common.bao_request import bao_request  # noqa: E402

W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/dbrotation"
NET, SUBNET, PG_IP, BAO_IP = "dbrot_net", "10.254.45.0/24", "10.254.45.70", "10.254.45.90"
PG, BAO, HOST = "dbrot-postgres", "dbrot-bao", "vault.lan.test"
FAILED = 0
AUDIT = []
rotate_mod.write_audit = lambda actor, event, detail, source, path=None: AUDIT.append((event, detail, path))


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if ok and res.returncode != 0:
        raise SystemExit(f"failed: {cmd}\n{res.stdout}{res.stderr}")
    return res


def cleanup():
    sh(["docker", "rm", "-f", PG, BAO], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


def signs_in(user, password, tries=1):
    """A sign-in to Postgres at its network address as user (scram: 127.0.0.1 is trusted inside the image), as
    Keycloak connects: True when it works (tries, a second
    apart)."""
    for i in range(tries):
        res = sh(["docker", "exec", "-e", f"PGPASSWORD={password}", PG, "psql", "-tA",
                  f"host={PG_IP} user={user} dbname=keycloak sslmode=require", "-c", "SELECT 1"], ok=False)
        if res.stdout.strip() == "1":
            print(f"    (signed in as {user} after {i + 1} attempt(s))") if i else None
            return True
        time.sleep(1)
    print(f"    (sign-in as {user} refused: {res.stderr.strip()[-160:]})")
    return False


def sql(query, user="fabric_admin"):
    return sh(["docker", "exec", PG, "psql", "-tA", "-U", user, "-d", "keycloak", "-c", query], ok=False).stdout.strip()


def role(name):
    return sql(f"SELECT rolsuper::text || rolcanlogin::text FROM pg_roles WHERE rolname = '{name}'")


def saved():
    return yaml.safe_load(open(SECRETS))["keycloak_db_password"]


cleanup()
shutil.rmtree(W, ignore_errors=True)
certs = os.path.join(W, "certs")
os.makedirs(certs)
os.chdir(certs)
sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root_ca.crt -days 2 -subj '/CN=Test Root' "
   "-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign")
for name, sans in (("bao", f"DNS:{HOST}"), ("postgres", "DNS:postgres")):
    sh(f"openssl req -newkey rsa:2048 -nodes -keyout {name}.key -out {name}.csr -subj '/CN={sans[4:]}'")
    with open(f"{name}.ext", "w") as f:
        f.write(f"subjectAltName={sans}\nextendedKeyUsage=serverAuth\n")
    sh(f"openssl x509 -req -in {name}.csr -CA root_ca.crt -CAkey root.key -CAcreateserial -out {name}.crt -days 2 "
       f"-extfile {name}.ext")
os.makedirs(os.path.join(W, "pgcerts"))
for f in ("postgres.crt", "postgres.key"):
    shutil.copy(f, os.path.join(W, "pgcerts", f))
sh(["chown", "-R", "999:999", os.path.join(W, "pgcerts")])
os.chmod(os.path.join(W, "pgcerts", "postgres.key"), 0o600)
sh(["chmod", "644", "bao.key"])                  # the OpenBao container's own user reads it
os.makedirs(os.path.join(W, "config"))
with open(os.path.join(W, "config", "test.hcl"), "w") as f:
    f.write('storage "inmem" {}\ndisable_mlock = true\nui = false\n'
            'listener "tcp" {\n  address = "0.0.0.0:8200"\n  tls_cert_file = "/openbao/certs/bao.crt"\n'
            '  tls_key_file = "/openbao/certs/bao.key"\n}\n')

lock = read_images_lock(os.path.join(REPO, "config"))
sh(["docker", "network", "create", "--subnet", SUBNET, NET])
P0 = "Initial-" + os.urandom(8).hex()
sh(["docker", "run", "-d", "--name", PG, "--network", NET, "--ip", PG_IP, "--network-alias", "postgres",
    "-e", "POSTGRES_DB=keycloak", "-e", "POSTGRES_USER=keycloak", "-e", f"POSTGRES_PASSWORD={P0}",
    "-v", f"{W}/pgcerts:/etc/postgres/certs:ro", lock["postgres"]["ref"], "postgres", "-c", "ssl=on",
    "-c", "ssl_cert_file=/etc/postgres/certs/postgres.crt", "-c", "ssl_key_file=/etc/postgres/certs/postgres.key"])
sh(["docker", "run", "-d", "--name", BAO, "--network", NET, "--ip", BAO_IP, "--entrypoint", "bao",
    "-v", f"{certs}:/openbao/certs:ro", "-v", f"{W}/config:/openbao/config:ro", lock["openbao"]["ref"],
    "server", "-config=/openbao/config/test.hcl"])
v = {"ip_openbao": BAO_IP, "hostname_openbao": HOST, "openbao_ca_file": os.path.join(certs, "root_ca.crt"),
     "deploy_base_dir": W}
for _ in range(60):
    ready = sh(["docker", "exec", PG, "pg_isready", "-U", "keycloak"], ok=False).returncode == 0
    if ready and signs_in("keycloak", P0):
        break
    time.sleep(2)
for _ in range(30):
    try:
        if bao_request(v, "GET", "sys/health")[0] in (200, 429, 472, 473, 501, 503):
            break
    except ValidationError:
        pass
    time.sleep(1)
init = bao_request(v, "POST", "sys/init", body={"secret_shares": 1, "secret_threshold": 1})[1]
bao_request(v, "POST", "sys/unseal", body={"key": init["keys"][0]})
TOKEN = init["root_token"]
sql("CREATE TABLE realm (id text); INSERT INTO realm VALUES ('master');", user="keycloak")   # Keycloak's data so far
check("Postgres (TLS, alias postgres) and OpenBao (TLS, unsealed) are up; Keycloak's user signs in",
      signs_in("keycloak", P0) and bao_request(v, "GET", "sys/health")[0] == 200)

SECRETS = os.path.join(W, "fabric-secrets.yml")
with open(SECRETS, "w") as f:
    yaml.safe_dump({"keycloak_db_password": P0}, f)
RECORD = os.path.join(W, "db-rotation.json")
rotate_mod.DB_ROTATION_FILE = RECORD
APPLIED = []


def apply(actor, source):
    APPLIED.append(saved())
    return True, ""


ADMIN_PW = "Admin" + os.urandom(12).hex()
orig_rotate = rotate_mod.rotate_db_password


def rotate(*a, **kw):                            # every rotation here records to the test's file
    return orig_rotate(*a, **{**kw, "record": RECORD})


import fabriclib.setup.ensure_db_rotation as ensure_mod  # noqa: E402
ensure_mod.rotate_db_password = rotate
try:
    ARCHIVE = os.path.join(W, "install-archive")             # setup passes the install's own (0.6.3 upgrade test)
    os.makedirs(ARCHIVE)
    ensure_mod.rotate_db_password = orig_rotate             # the take-over writes where it is told
    state = configure_db_engine(v, TOKEN, ADMIN_PW, apply, container=PG, secrets_file=SECRETS, archive=ARCHIVE)
    ensure_mod.rotate_db_password = rotate
    check("take-over: its record and audit line go to the install's archive it is given, not where the code runs",
          json.load(open(os.path.join(ARCHIVE, "db-rotation.json")))["ok"]
          and AUDIT[-1][2] == os.path.join(ARCHIVE, "audit.log"), AUDIT[-1:])
    shutil.copy(os.path.join(ARCHIVE, "db-rotation.json"), RECORD)
    P1 = saved()
    check("take-over: OpenBao's static role made, the password rotated at once and saved, Keycloak applied with it",
          state == "taken over" and P1 != P0 and APPLIED == [P1], (state, APPLIED))
    check("...Keycloak signs in as its own role with the new password; the old role and password are refused",
          signs_in("keycloak_db", P1) and not signs_in("keycloak", P0) and not signs_in("keycloak_db", P0))
    check("...Postgres has its own admin (a superuser, OpenBao's); Keycloak's role is none; the bootstrap role locked",
          role("fabric_admin") == "truetrue" and role("keycloak_db") == "falsetrue" and role("keycloak") == "truefalse"
          and signs_in("fabric_admin", ADMIN_PW), (role("fabric_admin"), role("keycloak_db"), role("keycloak")))
    check("...Keycloak's role owns its database and the tables made before, and uses them",
          sql("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'keycloak'") == "keycloak_db"
          and sql("SELECT tableowner FROM pg_tables WHERE tablename = 'realm'") == "keycloak_db"
          and sh(["docker", "exec", "-e", f"PGPASSWORD={P1}", PG, "psql", "-tA",
                  f"host={PG_IP} user=keycloak_db dbname=keycloak sslmode=require", "-q", "-c",
                  "INSERT INTO realm VALUES ('lan'); SELECT count(*) FROM realm"], ok=False).stdout.strip() == "2",
          sql("SELECT tableowner FROM pg_tables WHERE tablename = 'realm'"))
    check("...and its user name is saved with the password (Keycloak's settings follow)",
          yaml.safe_load(open(SECRETS)).get("keycloak_db_user") == "keycloak_db")
    rec = json.load(open(RECORD))
    check("...recorded and audited", rec["ok"] and AUDIT[-1][0] == "DB_ROTATE", (rec, AUDIT))
    again = configure_db_engine(v, TOKEN, ADMIN_PW, apply, container=PG, secrets_file=SECRETS, archive=ARCHIVE)
    check("converging again changes nothing (no rotation, Keycloak left alone)",
          again == "converged" and saved() == P1 and len(APPLIED) == 1 and signs_in("keycloak_db", P1))
    os.remove(os.path.join(ARCHIVE, "db-rotation.json"))        # a reinstall: OpenBao kept, the archive not
    configure_db_engine(v, TOKEN, ADMIN_PW, apply, container=PG, secrets_file=SECRETS, archive=ARCHIVE)
    back = json.load(open(os.path.join(ARCHIVE, "db-rotation.json")))
    age = time.time() - datetime.datetime.fromisoformat(back["when"]).timestamp()
    check("a missing record is rebuilt from OpenBao's own time of the last rotation (no rotation for it)",
          back["ok"] and 0 <= age < 600 and saved() == P1 and len(APPLIED) == 1, (back, age))
    rotate(v, TOKEN, apply=apply, secrets_file=SECRETS)
    P2 = saved()
    check("a rotation: a new password, saved and applied; the previous one refused",
          P2 not in (P0, P1) and APPLIED[-1] == P2 and signs_in("keycloak_db", P2) and not signs_in("keycloak_db", P1))

    # refusals
    try:
        rotate(v, "not-a-token", apply=apply, secrets_file=SECRETS)
        check("refused: a rotation OpenBao does not allow", False)
    except ValidationError as e:
        check("refused: a rotation OpenBao does not allow; the old password keeps working, the failure recorded",
              "old password keeps working" in str(e) and signs_in("keycloak_db", P2) and saved() == P2
              and json.load(open(RECORD))["ok"] is False, e)
    try:
        rotate(v, TOKEN, apply=lambda a, s: (False, "unhealthy"), secrets_file=SECRETS)
        check("refused: Keycloak not coming back with its new password", False)
    except ValidationError as e:
        check("refused: Keycloak not coming back with its new password (raised and recorded)",
              "did not come back" in str(e) and json.load(open(RECORD))["ok"] is False, e)
    status, data = bao_request(v, "POST", "database/config/postgres", token=TOKEN, body={
        "plugin_name": "postgresql-database-plugin", "allowed_roles": ["keycloak"], "verify_connection": True,
        "connection_url": f"postgresql://{{{{username}}}}:{{{{password}}}}@{PG_IP}:5432/keycloak"
                          "?sslmode=verify-full&sslrootcert=/openbao/certs/root_ca.crt",
        "username": "fabric_admin", "password": ADMIN_PW})
    check("refused: OpenBao reaching Postgres by a name its certificate does not carry (verify-full holds)",
          status >= 400, (status, data))

    # a reinstall: the secrets are kept, Postgres starts on an empty data folder (found by the 0.6.3 sandbox)
    from fabriclib.setup.ensure_db_rotation import align_postgres_roles  # noqa: E402
    check("before the take-over nothing is aligned (keycloak_db_user not in the secrets)",
          align_postgres_roles({"keycloak_db_password": "x", "postgres_admin_password": "y"}, PG) is False)
    sh(["docker", "rm", "-f", PG])
    sh(["docker", "run", "-d", "--name", PG, "--network", NET, "--ip", PG_IP, "--network-alias", "postgres",
        "-e", "POSTGRES_DB=keycloak", "-e", "POSTGRES_USER=keycloak", "-e", f"POSTGRES_PASSWORD={P0}",
        "-v", f"{W}/pgcerts:/etc/postgres/certs:ro", lock["postgres"]["ref"], "postgres", "-c", "ssl=on",
        "-c", "ssl_cert_file=/etc/postgres/certs/postgres.crt", "-c", "ssl_key_file=/etc/postgres/certs/postgres.key"])
    for _ in range(60):
        if sh(["docker", "exec", PG, "pg_isready", "-U", "keycloak"], ok=False).returncode == 0                 and signs_in("keycloak", P0):
            break
        time.sleep(2)
    kept = yaml.safe_load(open(SECRETS))
    kept["postgres_admin_password"] = ADMIN_PW
    aligned = align_postgres_roles(kept, PG)
    check("reinstall: a fresh Postgres gets Keycloak's role with the kept password, its own admin, the bootstrap locked",
          aligned and signs_in("keycloak_db", kept["keycloak_db_password"]) and role("keycloak_db") == "falsetrue"
          and role("fabric_admin") == "truetrue" and role("keycloak") == "truefalse"
          and sql("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'keycloak'") == "keycloak_db")
    check("...and aligning again changes nothing", align_postgres_roles(kept, PG)
          and signs_in("keycloak_db", kept["keycloak_db_password"]))
finally:
    if not os.environ.get("KEEP"):
        cleanup()
print("\nall passed" if not FAILED else f"\n{FAILED} failed")
sys.exit(1 if FAILED else 0)
