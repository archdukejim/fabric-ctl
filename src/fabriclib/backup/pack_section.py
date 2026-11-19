import hashlib
import os
import subprocess
import tempfile

from fabriclib.common.errors import ValidationError

TAR = ["tar", "--create", "--file=-", "--xattrs", "--xattrs-include=*", "--acls", "--numeric-owner", "--sparse",
       "--directory=/"]


def pack_section(dest, paths, recipient, extra_dir=None):
    """Purpose: one section's file of a bundle (manual 1.3.7.2), streamed `tar | zstd | age` so nothing of it is ever
             written unencrypted; owners, modes, ACLs and extended attributes kept (SYSVOL's NT ACLs are xattrs).
    Inputs:  dest — the section's file, <section>.tar.zst.age, written as dest + ".part" and renamed when whole;
             paths — [(abs path, [abs paths or file-name patterns such as "*.ldb" to leave out])] from section_paths
             or backup_plan; recipient — the bundle's public key;
             extra_dir — a folder of online dumps (1.3.7.4) packed under its own absolute path, or None.
    Returns: {"file": basename, "size": int, "sha256": hex} of the encrypted file.
    Fails:   ValidationError when tar, zstd or age fails (the .part file is removed); OSError.
    Feeds:   make_bundle."""
    names = [p.lstrip("/") for p, _ in paths] + ([extra_dir.lstrip("/")] if extra_dir else [])
    excludes = [f"--exclude={s.lstrip('/')}" for _, skip in paths for s in skip]
    part = dest + ".part"
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        errs = {n: tempfile.TemporaryFile() for n in ("tar", "zstd", "age")}
        tar = subprocess.Popen([*TAR, *excludes, "--", *names] if names else [*TAR, "--files-from=/dev/null"],
                               stdout=subprocess.PIPE, stderr=errs["tar"])
        zstd = subprocess.Popen(["zstd", "-q", "-T0", "-3", "-c"], stdin=tar.stdout, stdout=subprocess.PIPE,
                                stderr=errs["zstd"])
        tar.stdout.close()
        age = subprocess.Popen(["age", "-r", recipient], stdin=zstd.stdout, stdout=fd, stderr=errs["age"])
        zstd.stdout.close()
        for proc in (tar, zstd, age):
            proc.wait()
        # tar exits 1 when a file changed while it read it: only a cold copy is read that way, so it is not whole
        failed = [n for n, p in (("tar", tar), ("zstd", zstd), ("age", age)) if p.returncode != 0]
    finally:
        os.close(fd)
    if failed:
        os.remove(part)
        errs[failed[0]].seek(0)
        why = errs[failed[0]].read().decode(errors="replace").strip().splitlines()
        raise ValidationError(f"{os.path.basename(dest)}: {failed[0]} failed: {why[-1] if why else 'no reason'}")
    digest = hashlib.sha256()
    with open(part, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    os.replace(part, dest)
    return {"file": os.path.basename(dest), "size": os.path.getsize(dest), "sha256": digest.hexdigest()}
