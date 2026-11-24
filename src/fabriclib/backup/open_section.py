import os
import subprocess
import tarfile
import tempfile

from fabriclib.common.errors import ValidationError

UNTAR = ["tar", "--extract", "--file=-", "--xattrs", "--xattrs-include=*", "--acls", "--numeric-owner",
         "--same-permissions", "--same-owner"]


def open_section(path, section, identity, dest="/"):
    """Purpose: unpack one section of a checked bundle (check_bundle) into place, `age -d | zstd -d | tar -x`, owners,
             modes, ACLs and extended attributes as they were.
    Inputs:  path — the bundle; section — its name; identity — the bundle's private key (bundle_key_from.py);
             dest — where the archive's paths (absolute paths without their slash) go: "/" to put them back,
             or a scratch folder (an online dump read before it is loaded).
    Returns: None.
    Fails:   ValidationError when age, zstd or tar fails (a wrong key, a section cut short); KeyError when the
             section is not in the bundle.
    Feeds:   restore_bundle, restore_section."""
    with tarfile.open(path, mode="r:") as outer:
        src = outer.extractfile(f"{section}.tar.zst.age")
        rid, wid = os.pipe()
        os.write(wid, identity.encode() + b"\n")
        os.close(wid)
        errs = {n: tempfile.TemporaryFile() for n in ("age", "zstd", "tar")}
        age = subprocess.Popen(["age", "-d", "-i", f"/dev/fd/{rid}"], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=errs["age"], pass_fds=(rid,))
        os.close(rid)
        zstd = subprocess.Popen(["zstd", "-q", "-d", "-c"], stdin=age.stdout, stdout=subprocess.PIPE,
                                stderr=errs["zstd"])
        age.stdout.close()
        tar = subprocess.Popen([*UNTAR, f"--directory={dest}"], stdin=zstd.stdout, stderr=errs["tar"])
        zstd.stdout.close()
        try:
            for chunk in iter(lambda: src.read(1 << 20), b""):
                age.stdin.write(chunk)
        except BrokenPipeError:
            pass
        finally:
            age.stdin.close()
        for proc in (age, zstd, tar):
            proc.wait()
    failed = [n for n, p in (("age", age), ("zstd", zstd), ("tar", tar)) if p.returncode != 0]
    if failed:
        errs[failed[0]].seek(0)
        why = errs[failed[0]].read().decode(errors="replace").strip().splitlines()
        raise ValidationError(f"section {section}: {failed[0]} failed: {why[-1] if why else 'no reason'}")

