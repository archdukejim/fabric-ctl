import contextlib
import io
import json
import os
import shutil
import tarfile
import time

from fabriclib.backup.bundle_name import bundle_name
from fabriclib.backup.make_bundle_key import make_bundle_key
from fabriclib.backup.pack_section import pack_section
from fabriclib.backup.seal_bundle_key import seal_bundle_key
from fabriclib.backup.sections import ORDER, SECTIONS
from fabriclib.common.errors import ValidationError

FORMAT = 1
FOLDER = "/var/backups/fabric"
README = """fabric backup bundle — {host}, {when} UTC ({kind}, {method})

manifest.json        what is inside: the sections, their sizes and SHA-256 (no secret)
key.age              this bundle's own key, encrypted {opened}
<section>.tar.zst.age  one per section, encrypted to that key

Open a section without fabric (manual 1.3.7.2):
  age -d {how} key.age > bundle.key          # the bundle's key: keep it as secret as the bundle
  age -d -i bundle.key dns.tar.zst.age | zstd -d | tar -t

Whoever opens this bundle has your CA, your vault and your domain.
"""


def make_bundle(plan, host, meta, kind, passphrase=None, public_key=None, folder=FOLDER):
    """Purpose: write one bundle (manual 1.3.7.2, decision 2.1.3.6): a fresh key pair; each section packed and
             encrypted to it; the key sealed with the passphrase or the public key; then one plain tar of
             manifest.json, README.txt, key.age and the sections, written whole or not at all.
    Inputs:  plan — [(section, paths, extra_dir)] in any order, paths from section_paths (or [] for a section not
             installed), extra_dir a folder of online dumps or None; host — the host's name; meta — dict for the
             manifest: fabric_version, commit, domain, host_ip, lan_cidr, base, method ("cold" or "online");
             kind — bundle_name.KINDS; passphrase / public_key — exactly one; folder — where bundles live.
    Returns: the bundle's path (0600 in a 0700 folder).
    Fails:   ValidationError when a bundle of the same name exists, or from pack_section or seal_bundle_key
             (nothing is left: the staging folder and the .part file are removed); ValueError from bundle_name;
             OSError.
    Feeds:   backup_online, backup_cold."""
    os.makedirs(folder, mode=0o700, exist_ok=True)
    os.chmod(folder, 0o700)
    name = bundle_name(host, kind)
    path = os.path.join(folder, name)
    if os.path.exists(path):
        raise ValidationError(f"{name} already exists (two bundles in one second): nothing was written")
    stage = os.path.join(folder, f".{name}.stage")
    os.makedirs(stage, mode=0o700)
    try:
        identity, recipient = make_bundle_key()
        key_age = seal_bundle_key(identity, passphrase=passphrase, public_key=public_key)
        del identity
        by_name = {section: rest for section, *rest in plan}
        sections = []
        for section in ORDER:
            paths, extra, around = (list(by_name.get(section, ())) + [[], None, None])[:3]
            with around() if around else contextlib.nullcontext():
                entry = pack_section(os.path.join(stage, f"{section}.tar.zst.age"), paths, recipient, extra)
            entry.update(name=section, what=SECTIONS[section]["what"], empty=not paths and not extra)
            sections.append(entry)
        manifest = dict(meta, format=FORMAT, host=host, kind=kind, made=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                        time.gmtime()), opened_by="passphrase" if passphrase is not None else public_key,
                        sections=sections)
        readme = README.format(host=host, when=manifest["made"], kind=kind, method=meta.get("method", "?"),
                               opened="with a passphrase" if passphrase is not None else f"to {public_key}",
                               how="" if passphrase is not None else "-i <your private key file>")
        members = [("manifest.json", json.dumps(manifest, indent=2).encode() + b"\n"),
                   ("README.txt", readme.encode()), ("key.age", key_age)]
        part = path + ".part"
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out, tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for member, data in members:
                info = tarfile.TarInfo(member)
                info.size, info.mode, info.mtime = len(data), 0o600, int(time.time())
                tar.addfile(info, io.BytesIO(data))
            for entry in sections:
                tar.add(os.path.join(stage, entry["file"]), arcname=entry["file"])
        os.replace(part, path)
        return path
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        if os.path.exists(path + ".part"):
            os.remove(path + ".part")
