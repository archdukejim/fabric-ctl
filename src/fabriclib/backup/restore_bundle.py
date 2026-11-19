import ipaddress
import os
import shutil

from fabriclib.backup.backup_lock import backup_lock
from fabriclib.backup.backup_plan import DUMPS
from fabriclib.backup.bundle_key_from import bundle_key_from
from fabriclib.backup.check_bundle import check_bundle
from fabriclib.backup.open_section import open_section
from fabriclib.backup.restore_pending import write_restore_pending
from fabriclib.backup.sections import ORDER
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.write_audit import write_audit
from fabriclib.setup.detach.constants import RECORD

CHANGEABLE = ("host_ip", "lan_cidr", "lan_gateway")
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


def _check_changes(changes, manifest):
    """Purpose: the settings a whole restore may change (manual 1.3.7.7), checked against the bundle's own before
             anything is unpacked.
    Inputs:  changes — {key: value}; manifest — the bundle's (host_ip, lan_cidr, lan_gateway as it was made).
    Returns: {key: (old, new)} of what changes.
    Fails:   ValidationError: a key that cannot change (the domain, the DC's name, the host's name: renamed after the
             restore, 4.2.4.3), an address that is not one, a gateway or address outside the subnet, the host on the
             gateway's address.
    Feeds:   restore_bundle."""
    bad = sorted(set(changes) - set(CHANGEABLE))
    if bad:
        raise ValidationError(f"a restore changes only {', '.join(CHANGEABLE)}; not {', '.join(bad)}"
                              + (" (rename the host after the restore: manual 4.2.4.3)" if "hostname" in bad else ""))
    new = {k: changes.get(k, manifest.get(k)) for k in CHANGEABLE}
    try:
        net = ipaddress.ip_network(new["lan_cidr"], strict=False)
        host, gateway = ipaddress.ip_address(new["host_ip"]), ipaddress.ip_address(new["lan_gateway"])
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"the new network is not valid: {exc}") from None
    if host not in net or gateway not in net:
        raise ValidationError(f"{host} and its gateway {gateway} must both be in {net}")
    if host == gateway:
        raise ValidationError(f"the host's address {host} is the gateway's")
    return {k: (manifest.get(k), new[k]) for k in CHANGEABLE if str(manifest.get(k)) != str(new[k])}


def restore_bundle(base, path, key, changes=None, package_version="?", actor="root", source="cli"):
    """Purpose: a whole restore (manual 1.3.7.6, 1.3.7.7) onto a host where fabric is not installed: the bundle checked
             and opened, every section put back in place, the address changes written, and for an online bundle its
             dumps left in RAM for setup to load (restore-pending.json); setup is the caller's next step.
    Inputs:  base — install root; path — the bundle; key — {"passphrase"} or {"private_key"} (read_backup_key);
             changes — {host_ip, lan_cidr, lan_gateway} to change, or None; package_version — the installed package's
             version; actor, source — who (audit).
    Returns: {"manifest": the bundle's, "changed": {key: (old, new)}, "pending": [sections setup loads]}.
    Fails:   ValidationError: fabric installed here, a bundle that is not whole, made by a newer fabric or for another
             install root, a wrong key, a change refused (nothing is unpacked before these checks); from open_section.
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
        changed = _check_changes(changes or {}, manifest)
        identity = bundle_key_from(path, **key)
        shutil.rmtree(DUMPS, ignore_errors=True)
        for section in ORDER:
            open_section(path, section, identity, dest="/")
        del identity
        if changed:
            v = load_vars(vars_file)
            v.update({k: new for k, (_, new) in changed.items()})
            save_vars(v, vars_file)
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
    return {"manifest": manifest, "changed": changed, "pending": sorted(pending)}
