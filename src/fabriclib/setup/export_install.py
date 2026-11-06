import os
import subprocess
import time

from fabriclib.common.console import info, ok
from fabriclib.common.errors import ValidationError
from fabriclib.secrets.export_secrets import export_secrets
from fabriclib.secrets.secrets_in_openbao import secrets_in_openbao
from fabriclib.setup.uninstall import DIRS, TIMERS
from fabriclib.system.control_stack import control_stack

ROOT_DIR = "@root"          # absolute paths outside the install root (the vault key folder, external data)
STOP_WAIT = 90              # seconds the containers get to be gone once their units have stopped (2.3.1.53)

README = """fabric export — {host}, {when}

Everything fabric had on this host, copied with owners and modes kept
(cp -a) while the stack was stopped, so databases are consistent:

  fabric/            config, vars.yaml, audit log; fabric-secrets.yml = fabric's
                     own secrets exported from OpenBao (PLAINTEXT)
  stepca/            the CA: root + intermediate keys, database
  openbao/           OpenBao's data (your apps/ secrets, encrypted)
  @root/…            OpenBao's vault key and unlock methods — with openbao/ this
                     OPENS THE VAULT
  samba/             the domain: people, groups, machines, devices, device roles, policies
  keycloak/, postgres/  Keycloak and its database (TOTP enrolments, sessions)
  bind9/, nginx/, webui/  zones, TSIG material, certificates

Whoever has this folder has your CA and your vault. Keep it root-only and
offline; delete it when you no longer need it.
"""


def _copy(src, dest_parent):
    """Purpose: copy a folder with owners and modes kept.
    Inputs:  src — folder; dest_parent — folder to copy into (created).
    Returns: None; dest_parent/<basename of src>.
    Fails:   ValidationError when `cp -a` fails: the export is not whole, and nothing has been removed; OSError from
             makedirs.
    Feeds:   export_install."""
    os.makedirs(dest_parent, exist_ok=True)
    res = subprocess.run(["cp", "-a", src, dest_parent], capture_output=True, text=True)
    if res.returncode != 0:
        raise ValidationError(f"the export could not copy {src}: {res.stderr.strip()[:300]}. It is not whole, so "
                              "nothing was uninstalled; fabric is stopped: sudo fabricctl start, then try again")


def _still_running(base):
    """Purpose: the containers of this install still running, whatever systemd says of their units.
    Inputs:  base — the install's deploy base; Compose records each project's folder on its containers.
    Returns: sorted [name]; only those of fabric's own folders (DIRS): another project, even in the same base, is not.
    Fails:   ValidationError when Docker cannot say: an export must not assume.
    Feeds:   _stop_stack."""
    res = subprocess.run(["docker", "ps", "--format",
                          '{{.Names}}\t{{.Label "com.docker.compose.project.working_dir"}}'],
                         capture_output=True, text=True)
    if res.returncode != 0:
        raise ValidationError(f"the export could not ask Docker what is running: {res.stderr.strip()[:300]}. "
                              "Nothing was uninstalled")
    rows = (line.split("\t") + [""] for line in res.stdout.splitlines())
    folders = {os.path.join(base, name) for name in DIRS}
    return sorted(row[0] for row in rows if row[1] in folders)


def _stop_stack(base):
    """Purpose: stop fabric and prove it has stopped before anything is copied. `systemctl stop fabric.target` returned
             in under a second with Postgres still running: a unit is ordered Before= the target, so the target's stop
             ends first and the units' stops, which systemctl does not wait for, come after (2.3.1.53).
    Inputs:  base — the install's deploy base.
    Returns: None. Nothing of this install is running, and no timer of fabric's can start anything during the copy.
    Fails:   ValidationError from control_stack, or when a container of this install is still running after STOP_WAIT:
             the copy would not be consistent, so there is none.
    Feeds:   export_install."""
    # one that is not there is no failure
    subprocess.run(["systemctl", "stop", *[f"{t}.timer" for t in TIMERS]], capture_output=True)
    control_stack("stop")                          # names every unit, so systemctl waits for each
    end = time.time() + STOP_WAIT
    running = _still_running(base)
    while running and time.time() < end:
        time.sleep(1)
        running = _still_running(base)
    if running:
        raise ValidationError(f"fabric did not stop: {', '.join(running)} still running after {STOP_WAIT} s. A copy "
                              "now would not be consistent, so there is none, and nothing was uninstalled")


def export_install(ctx, dest):
    """Purpose: export all of fabric's data before an uninstall: fabric's secrets out of OpenBao while it
             runs, then the stack is stopped and every fabric folder, the vault key folder and any data folder
             outside the install root are copied cold, with a README.
    Inputs:  ctx — SetupContext with state loaded (vars openbao_key_dir, keycloak_data_dir, postgres_data_dir,
             hostname; secrets_file); dest — folder already accepted by check_export_dir.
    Returns: dest (str), root 0700: DIRS copies, @root/<abs path> for outside folders, README.txt, and
             fabric/config/fabric-secrets.yml (PLAINTEXT) when the secrets were in OpenBao. The stack stays stopped.
    Fails:   ValidationError from export_secrets (OpenBao unreachable), from _stop_stack (fabric did not stop) and
             from _copy; OSError.
    Feeds:   run_uninstall_command (before uninstall)."""
    os.makedirs(dest, mode=0o700, exist_ok=True)
    os.chown(dest, 0, 0)
    os.chmod(dest, 0o700)
    v = ctx.vars
    secrets = os.path.join(dest, "fabric", "config", "fabric-secrets.yml")
    if secrets_in_openbao(ctx.secrets_file):
        os.makedirs(os.path.dirname(secrets), mode=0o700, exist_ok=True)
        export_secrets(ctx.secrets_file, secrets)
    info("stopping fabric for a consistent copy")
    _stop_stack(ctx.deploy_base)
    for name in DIRS:
        if os.path.isdir(ctx.path(name)):
            _copy(ctx.path(name), dest)
    outside = [v.get("openbao_key_dir")] + [v.get(k) for k in ("keycloak_data_dir", "postgres_data_dir")]
    for path in outside:
        if path and os.path.isdir(path) and not path.startswith(ctx.deploy_base + os.sep):
            _copy(path, os.path.join(dest, ROOT_DIR, os.path.dirname(path).lstrip("/")))
    with open(os.path.join(dest, "README.txt"), "w") as f:
        f.write(README.format(host=v.get("hostname") or "?", when=time.strftime("%Y-%m-%d %H:%M")))
    size = subprocess.run(["du", "-sh", dest], capture_output=True, text=True).stdout.split("\t")[0]
    ok(f"exported to {dest} ({size}, root only)")
    return dest
