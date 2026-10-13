import glob
import os
import shutil
import subprocess

from fabriclib.common.console import info, ok, warn
from fabriclib.common.errors import ValidationError
from fabriclib.images.constants import STATE as IMAGE_STATE
from fabriclib.setup.common.service_account_name import service_account_name
from fabriclib.undo.remove_host_account import remove_host_account
from fabriclib.undo.undo_firewall import undo_firewall
from fabriclib.undo.undo_member import undo_member
from fabriclib.undo.undo_resolver import undo_resolver
from fabriclib.undo.undo_time import undo_time
from fabriclib.undo.undo_trust import undo_trust
from fabriclib.vault.ssh.apply_host_ssh_cert import apply_host_ssh_cert

# ldap, fabric-directory-sync and dirsrv: 389-DS, gone since 0.5.0 (S7); still removed where an older install
# left them
UNITS = ["fabric-web", "webui", "fluentbit", "kea", "freeradius", "samba", "adguard", "adguard-auth", "bind9-resolver",
         "adguard-filter", "fabric-agent", "fabric-federation", "fabric-scep-hook", "fabric-directory-sync", "nginx",
         "openbao", "keycloak",
         "postgres",
         "ldap", "stepca", "bind9", "fabric-firewall", "fabric-certs", "fabric-db-rotate", "fabric-dns-lists",
         "fabric-dns-log", "fabric-machines", "fabric-dhcp-names", "fabric-plan-watch", "fabric-host-managed",
         "fabric-ssh-hosts"]
TARGET = "/etc/systemd/system/fabric.target"
CONTAINERS = ["fabric-web", "webui", "fluentbit", "kea-dhcp4", "kea-ddns", "freeradius", "samba", "adguardhome",
              "oauth2-proxy-adguard", "bind9-resolver", "adguard-filter", "nginx", "openbao", "keycloak", "postgres",
              "dirsrv", "step-ca", "bind9"]
DIRS = ["fabric", "nginx", "bind9", "stepca", "dirsrv", "keycloak", "postgres", "webui", "openbao", "fluentbit", "kea",
        "freeradius", "samba", "federation", "adguard", "adguard-auth", "resolver", "dnsfilter"]
LOCAL_IMAGES = ["fabric/bind9:local", "fabric/stepca:local", "fabric/dirsrv:local", "fabric/keycloak:local",
                "fabric/web:local", "fabric/webui:local", "fabric/kea:local", "fabric/freeradius:local",
                "fabric/samba:local"]


def uninstall(ctx):
    """Purpose: remove fabric from this host: units, fabric.target, containers, fabric_net, local images, the
             host changes it made (undo/: its firewall rules — ufw off again if it was off before —, the resolver,
             chrony's files, CA trust, the host's domain membership; its SSH host certificate), data folders, the
             OpenBao key and runtime folders, the image rollback record (and /etc/fabric once empty), service accounts
             and the CLI wrapper (undo/uninstall_plan lists it).
    Inputs:  ctx — SetupContext (state reloaded): vars keycloak_data_dir/postgres_data_dir (deleted when outside
             deploy_base), tsig_keys names (their <deploy_base>/<name> folders), openbao_runtime_dir,
             openbao_admin_dir, openbao_udev_rules, openbao_key_dir, service_users, domain_file.
    Returns: None. Only fabric's own objects are touched (no global Docker prune, no Docker restart: Docker's
             daemon settings stay, as do apt packages). The vault data and key are gone afterwards — export first
             to keep them.
    Fails:   OSError from shutil.rmtree for the external data and key folders or os.remove; every command
             failure (systemctl, docker, iptables, userdel, update-ca-certificates) is ignored.
    Feeds:   cli main (`reinstall`), run_uninstall_command."""
    ctx.load_state()
    v = ctx.vars

    # the host's own computer account (1.6.11.8), removed while the DC still answers: in a federation the domain
    # outlives this site's DC
    for line in remove_host_account(ctx.config_dir, v, lambda: ctx.secrets):
        ok(line)
    try:                # this host's SSH host certificate and its trust of fabric's host CA (1.6.11.9.10)
        for line in apply_host_ssh_cert(v, [], ""):
            ok(line)
    except (ValidationError, OSError) as exc:
        warn(f"this host's SSH host certificate not removed ({exc}): remove /etc/ssh/fabric-host-cert-*.pub and "
             "/etc/ssh/sshd_config.d/11-fabric-host-cert.conf by hand")
    info("stopping and removing services")
    for timer in ("fabric-directory-sync", "fabric-certs", "fabric-db-rotate", "fabric-dns-lists", "fabric-dns-log",
                  "fabric-machines", "fabric-dhcp-names", "fabric-plan-watch", "fabric-host-managed",
                  "fabric-ssh-hosts"):
        subprocess.run(["systemctl", "disable", "--now", f"{timer}.timer"], capture_output=True)
    for unit in UNITS:
        subprocess.run(["systemctl", "disable", "--now", unit], capture_output=True)
        for path in (f"/etc/systemd/system/{unit}.service", f"/etc/systemd/system/{unit}.timer"):
            if os.path.exists(path):
                os.remove(path)
    subprocess.run(["systemctl", "disable", "--now", "fabric.target"], capture_output=True)
    if os.path.exists(TARGET):
        os.remove(TARGET)
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    for c in CONTAINERS:
        subprocess.run(["docker", "rm", "-f", c], capture_output=True)
    subprocess.run(["docker", "network", "rm", "fabric_net"], capture_output=True)
    subprocess.run(["docker", "rmi", *LOCAL_IMAGES], capture_output=True)
    ok("services, containers, fabric_net and local images removed")

    # the host changes fabric made, undone while their records (in the config folder) still exist
    for line in (undo_firewall(ctx.config_dir) + undo_resolver(ctx.config_dir) + undo_time(ctx.config_dir)
                 + undo_trust(v) + undo_member(ctx.config_dir)):
        ok(line)

    for key in ("keycloak_data_dir", "postgres_data_dir"):
        path = v.get(key)
        if path and not path.startswith(ctx.deploy_base + os.sep) and os.path.isdir(path):
            shutil.rmtree(path)
            ok(f"removed {path}")
    extra = [k.get("name") for k in (v.get("tsig_keys") or []) if k.get("name")]
    for name in DIRS + extra:
        shutil.rmtree(ctx.path(name), ignore_errors=True)
    for path in glob.glob(ctx.path("acme_*")):
        shutil.rmtree(path, ignore_errors=True)
    ok(f"removed fabric directories under {ctx.deploy_base}")
    signd = v.get("ad_ntp_signd_dir") or "/var/lib/samba/ntp_signd"
    shutil.rmtree(signd, ignore_errors=True)               # the DC's time-signing socket folder (2.1.13.1)
    try:
        os.rmdir(os.path.dirname(signd))                   # /var/lib/samba, when fabric's folder was all it held
    except OSError:
        pass
    shutil.rmtree(v.get("openbao_runtime_dir") or "/run/fabric/openbao", ignore_errors=True)
    shutil.rmtree(v.get("openbao_admin_dir") or "/run/fabric/openbao-admin", ignore_errors=True)
    rules = v.get("openbao_udev_rules") or "/etc/udev/rules.d/90-fabric-unlock.rules"
    if os.path.exists(rules):                   # the unlock-device kill switch
        os.remove(rules)
        subprocess.run(["udevadm", "control", "--reload"], capture_output=True)
    key_dir = v.get("openbao_key_dir")
    if key_dir and os.path.isdir(key_dir):
        shutil.rmtree(key_dir)
        ok(f"removed the OpenBao seal key ({key_dir}): its vault data is gone too")
    shutil.rmtree(os.path.dirname(IMAGE_STATE), ignore_errors=True)     # image rollback record: meaningless now
    etc = os.path.dirname(os.path.dirname(IMAGE_STATE))                  # /etc/fabric, if nothing else is in it
    if os.path.isdir(etc) and not os.listdir(etc):
        os.rmdir(etc)

    for key, ids in (v.get("service_users") or {}).items():
        name = service_account_name(key, ids)
        if subprocess.run(["id", name], capture_output=True).returncode == 0:
            subprocess.run(["userdel", name], capture_output=True)
            subprocess.run(["groupdel", name], capture_output=True)
    ok("service accounts removed")

    if os.path.exists("/usr/local/bin/fabricctl"):
        os.remove("/usr/local/bin/fabricctl")
    ok("fabricctl removed")
    warn("Docker's daemon settings and apt packages stay (`fabricctl setup --undo runtime` before uninstalling "
         "puts the daemon settings back)")
