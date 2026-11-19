import os
import shutil
import subprocess
import tempfile

from fabriclib.backup.backup_lock import backup_lock
from fabriclib.backup.backup_plan import DUMPS
from fabriclib.backup.bundle_key_from import bundle_key_from
from fabriclib.backup.check_bundle import check_bundle
from fabriclib.backup.load_directory_dump import load_directory_dump
from fabriclib.backup.live_paths import live_paths
from fabriclib.backup.load_signin_dump import load_signin_dump
from fabriclib.backup.make_backup import make_backup
from fabriclib.backup.open_section import open_section
from fabriclib.backup.restore_pending import write_restore_pending
from fabriclib.backup.section_of_key import section_of_key
from fabriclib.backup.section_paths import section_paths
from fabriclib.backup.sections import ORDER, SECTIONS
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.systemctl_up import systemctl_up
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit

# the units each section's restore stops while its state is replaced (manual 1.3.7.8)
UNITS = {"dns": ["bind9", "bind9-resolver", "adguard-filter"], "pki": ["stepca"], "directory": ["samba"],
         "signin": ["keycloak"], "dhcp": ["kea"], "settings": []}


def _clear(path, keep):
    """Purpose: a section's folder emptied before its copy goes in, so what was made after the bundle goes too; the
             deeper folders another section owns stay.
    Inputs:  path — the folder; keep — absolute folders inside it that stay.
    Returns: None.
    Fails:   OSError.
    Feeds:   restore_section."""
    for name in os.listdir(path):
        full = os.path.join(path, name)
        if any(k == full for k in keep):
            continue
        if any(k.startswith(full + os.sep) for k in keep):
            _clear(full, keep)
        elif os.path.isdir(full) and not os.path.islink(full):
            shutil.rmtree(full)
        else:
            os.remove(full)


def _bundle_vars(path, identity):
    """Purpose: the vars.yaml the bundle was made with, read from its settings section in a scratch folder.
    Inputs:  path — the bundle; identity — its key.
    Returns: dict.
    Fails:   ValidationError when the settings section holds no vars.yaml.
    Feeds:   restore_section."""
    scratch = tempfile.mkdtemp(prefix="fabric-restore-", dir="/run")
    try:
        open_section(path, "settings", identity, dest=scratch)
        found = [os.path.join(d, "vars.yaml") for d, _, files in os.walk(scratch) if "vars.yaml" in files
                 and d.endswith(os.path.join("fabric", "config"))]
        if not found:
            raise ValidationError("the bundle's settings hold no vars.yaml")
        return load_vars(found[0])
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def restore_section(base, config_dir, path, section, key, installed_version, actor="root", source="cli",
                    apply=None):
    """Purpose: one section of a bundle restored on a running install (manual 1.3.7.8): a safety bundle of the
             section (and settings, which holds the vars.yaml it is restored with) first, then the section's services
             stopped, its folders replaced, its vars.yaml keys replaced (the rest kept), an online dump loaded where it has one (into the running database, whose
             folder stays), the services started again and an apply run; audited.
    Inputs:  base — install root; config_dir — fabric's config folder; path — the bundle; section — its name;
             key — {"passphrase"} or {"private_key"}; installed_version — this install's fabric version; actor, source
             — who (audit); apply — callable running `fabricctl --apply` (tests), default the command.
    Returns: {"safety": the safety bundle's path, "keys": [vars.yaml keys replaced]}.
    Fails:   ValidationError: secrets alone (2.1.1.106 point 2), an unknown section, a bundle that is not whole, of
             another fabric version or of another install root, a wrong key, the safety bundle not made (nothing is
             restored then); from the loaders and open_section.
    Feeds:   run_restore_command (`--section`), the agent's backup restore route."""
    if section not in SECTIONS:
        raise ValidationError(f"no section {section!r}: one of {', '.join(ORDER)}")
    if SECTIONS[section].get("alone") is False:
        raise ValidationError("secrets is not restored alone: OpenBao holds every service's password, and alone it "
                              "would no longer match the running databases. Restore the whole bundle instead")
    manifest = check_bundle(path)
    if os.path.normpath(manifest.get("base") or base) != os.path.normpath(base):
        raise ValidationError(f"the bundle is of an install at {manifest['base']}, not {base}")
    if manifest.get("fabric_version") != installed_version:
        raise ValidationError(f"the bundle is of fabric {manifest.get('fabric_version')}, this install of "
                              f"{installed_version}: one section is restored only into the same version")
    identity = bundle_key_from(path, **key)
    v = load_vars(os.path.join(config_dir, "vars.yaml"))
    opened = manifest.get("opened_by")
    safety = make_backup(base, v, os.path.join(config_dir, "fabric-secrets.yml"), "manual", "online", actor=actor,
                         source=source, only={section, "settings"},
                         **({"passphrase": key["passphrase"]} if key.get("passphrase") is not None
                            else {"public_key": opened}))
    with backup_lock("a restore"):
        theirs = _bundle_vars(path, identity)
        units = [u for u in UNITS.get(section, [])
                 if subprocess.run(["systemctl", "is-active", "--quiet", u]).returncode == 0]
        if units:
            subprocess.run(["systemctl", "stop", *units], capture_output=True)
        try:
            live = live_paths(section, base, v) if manifest.get("method") == "online" else []
            for folder, keep in section_paths(section, base, v):
                _clear(folder, keep + live)
            shutil.rmtree(DUMPS, ignore_errors=True)
            open_section(path, section, identity, dest="/")
            replaced = []
            with vars_lock():
                ours = load_vars(os.path.join(config_dir, "vars.yaml"))
                for k in sorted(set(ours) | set(theirs)):
                    if section_of_key(k) == section:
                        replaced.append(k)
                        if k in theirs:
                            ours[k] = theirs[k]
                        else:
                            ours.pop(k, None)
                save_vars(ours, os.path.join(config_dir, "vars.yaml"))
            if manifest.get("method") == "online":
                folder = os.path.join(DUMPS, section)
                dumps = sorted(os.listdir(folder)) if os.path.isdir(folder) else []
                if section == "directory" and dumps:
                    write_restore_pending(config_dir, {"directory": os.path.join(folder, dumps[0])})
                    load_directory_dump(base, config_dir)
                if section == "signin" and "keycloak.pgdump" in dumps:
                    write_restore_pending(config_dir, {"signin": os.path.join(folder, "keycloak.pgdump")})
                    load_signin_dump(config_dir)
        finally:
            shutil.rmtree(DUMPS, ignore_errors=True)
            if units:
                systemctl_up(units, capture=True)
        (apply or (lambda: subprocess.run(["fabricctl", "--apply"], check=True)))()
    write_audit(actor, "RESTORE_SECTION", f"bundle={os.path.basename(path)} section={section} "
                f"safety={os.path.basename(safety)}", source=source)
    return {"safety": safety, "keys": replaced}
