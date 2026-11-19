import os
import shutil

from fabriclib.backup.backup_lock import backup_lock
from fabriclib.backup.backup_plan import DUMPS
from fabriclib.backup.bundle_key_from import bundle_key_from
from fabriclib.backup.check_bundle import check_bundle
from fabriclib.backup.check_changes import NETWORK, check_changes
from fabriclib.backup.old_address_uses import old_address_uses
from fabriclib.backup.open_section import open_section
from fabriclib.backup.restore_pending import write_restore_pending
from fabriclib.backup.sections import ORDER
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.write_audit import write_audit
from fabriclib.setup.common.network_problem import network_problem
from fabriclib.setup.detach.constants import RECORD

DUMP_FILES = {"directory": None, "secrets": "openbao.snap", "signin": "keycloak.pgdump"}


def _version(text):
    """Purpose: a fabric version as a comparable tuple.
    Inputs:  text — "0.10.1", "0.10.1~git…", or "?".
    Returns: (major, minor, patch), or None when it is not a version.
    Fails:   never.
    Feeds:   restore_bundle."""
    parts = (text or "").split("~")[0].split(".")
    try:
        return tuple(int(p) for p in parts[:3]) if len(parts) >= 3 else None
    except ValueError:
        return None


def restore_bundle(base, path, key, changes=None, package_version="?", actor="root", source="cli"):
    """Purpose: a whole restore (manual 1.3.7.6, 1.3.7.7) onto a host where fabric is not installed: the bundle checked
             and opened, every section put back in place, the address changes written, and for an online bundle its
             dumps left in RAM for setup to load (restore-pending.json); setup is the caller's next step.
    Inputs:  base — install root; path — the bundle; key — {"passphrase"} or {"private_key"} (read_backup_key);
             changes — {host_ip, lan_cidr, lan_gateway} to change, or None; package_version — the installed package's
             version; actor, source — who (audit).
    Returns: {"manifest": the bundle's, "changed": {key: (old, new)}, "pending": [sections setup loads],
             "leftover": [(setting, value)] still naming the old address or subnet after a move (old_address_uses)}.
    Fails:   ValidationError: fabric installed here, a bundle that is not whole, made by a newer fabric or for another
             install root, a wrong key, a change refused, a new address this
             host does not have yet (nothing is unpacked before these checks); from open_section.
    Feeds:   run_restore_command, the setup site's Restore from a backup."""
    vars_file = os.path.join(base, "fabric", "config", "vars.yaml")
    with backup_lock("a restore"):
        if os.path.exists(vars_file):
            raise ValidationError(f"fabric is installed here ({vars_file}): `sudo fabricctl uninstall` first, "
                                  "or restore one section with --section")
        manifest = check_bundle(path)
        made, have = _version(manifest.get("fabric_version")), _version(package_version)
        if made and have and made > have:
            raise ValidationError(f"the bundle was made by fabric {manifest['fabric_version']}, newer than this "
                                  f"package ({package_version}): install that version or newer first")
        if os.path.normpath(manifest.get("base") or base) != os.path.normpath(base):
            raise ValidationError(f"the bundle is of an install at {manifest['base']}, not {base}")
        changed = check_changes(changes or {}, manifest)
        new = {k: (changed[k][1] if k in changed else manifest.get(k)) for k in NETWORK}
        problem = network_problem(new) if all(new.values()) else ""
        if problem:                              # setup would stop on it, with fabric's data already in place
            raise ValidationError(f"{problem}. Give this host its new address first (its VLAN and netplan, manual "
                                  "4.2.4.8), then restore")
        identity = bundle_key_from(path, **key)
        shutil.rmtree(DUMPS, ignore_errors=True)
        for section in ORDER:
            open_section(path, section, identity, dest="/")
        del identity
        leftover = []
        if changed:
            v = load_vars(vars_file)
            v.update({k: value for k, (_, value) in changed.items()})
            save_vars(v, vars_file)
            if set(changed) & {"host_ip", "lan_cidr"} and manifest.get("host_ip") and manifest.get("lan_cidr"):
                leftover = old_address_uses(v, manifest["host_ip"], manifest["lan_cidr"])
        config = os.path.dirname(vars_file)
        secrets = os.path.join(DUMPS, "secrets", "fabric-secrets.yml")
        if os.path.exists(secrets):              # a cold bundle: setup imports fabric's secrets and shreds the file
            shutil.move(secrets, os.path.join(config, "fabric-secrets.yml"))
            os.chmod(os.path.join(config, "fabric-secrets.yml"), 0o600)
        pending = {}
        if manifest.get("method") == "online":
            for section, name in DUMP_FILES.items():
                folder = os.path.join(DUMPS, section)
                found = sorted(os.listdir(folder)) if os.path.isdir(folder) else []
                dump = name if name in found else next((f for f in found if f.endswith(".tar.bz2")), None)
                if dump and (name is None or dump == name):
                    pending[section] = os.path.join(folder, dump)
        write_restore_pending(config, pending)
        record = os.path.join(config, RECORD)
        if os.path.exists(record):                # a run record copied with the config: setup starts over
            os.remove(record)
    write_audit(actor, "RESTORE", f"bundle={os.path.basename(path)} made={manifest.get('made')} "
                f"changed={','.join(changed) or 'nothing'}", source=source)
    return {"manifest": manifest, "changed": changed, "pending": sorted(pending), "leftover": leftover}
