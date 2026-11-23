import os
import shutil
import subprocess
import tarfile

from fabriclib.backup.restore_pending import read_restore_pending, write_restore_pending
from fabriclib.common.errors import ValidationError

PARTS = ("private/", "state/", "etc/", "bind-dns/")   # the offline copy's folders, as Samba names them (/data/<part>)


def load_directory_dump(base, config_dir):
    """Purpose: before the DC first starts after an online bundle's restore (manual 1.3.7.6): the offline copy's
             databases put over the folders that were packed live, then its backup marks removed in the DC's own
             image (src/containers/samba/finish_restore.py), so Samba starts on the domain as it was. BIND's copy of
             the DNS partitions (bind-dns/dns: links into private/sam.ldb.d, and its keytab), which the copy does not
             bring, is made again there by Samba's `samba_upgradedns --dns-backend=BIND9_DLZ`, through
             src/containers/samba/make_bind_dns.py (found 2026-11-23 by the sandbox: the AD zone went unanswered);
             start_services then turns BIND's include on, as on a first install.
    Inputs:  base — install root (the DC's /data is base/samba/data); config_dir — fabric's config folder.
    Returns: True when a dump was loaded, False when none was pending.
    Fails:   ValidationError when the copy names a path outside its parts, the marks cannot be removed or BIND's copy
             cannot be made (the dump stays pending: setup can be run again); OSError.
    Feeds:   setup/start_services (before the samba unit starts)."""
    pending = read_restore_pending(config_dir)
    dump = pending.get("directory")
    if not dump:
        return False
    data = os.path.join(base, "samba", "data")
    subprocess.run(["systemctl", "stop", "samba"], capture_output=True)
    with tarfile.open(dump, "r:bz2") as tar:
        members = [m for m in tar.getmembers() if m.isfile() and m.name.startswith(PARTS)]
        for m in members:
            target = os.path.normpath(os.path.join(data, m.name))
            if not target.startswith(data + os.sep):
                raise ValidationError(f"the domain's copy names {m.name}, outside the DC's data: not restored")
        for m in members:
            target = os.path.join(data, m.name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with tar.extractfile(m) as src, open(target + ".restoring", "wb") as out:
                shutil.copyfileobj(src, out)
            os.chmod(target + ".restoring", m.mode & 0o777)
            os.chown(target + ".restoring", m.uid, m.gid)
            os.replace(target + ".restoring", target)
    compose = os.path.join(base, "samba", "docker-compose.yml")
    res = subprocess.run(["docker", "compose", "-f", compose, "run", "--rm", "--no-deps", "--entrypoint", "python3",
                          "samba", "/fabric/finish_restore.py"], capture_output=True, text=True, timeout=300)
    if res.returncode != 0:
        why = (res.stderr or res.stdout)[-300:]
        raise ValidationError(f"the restored domain's backup marks could not be removed: {why}")
    if not os.path.exists(os.path.join(data, "bind-dns", "dns", "sam.ldb")):
        res = subprocess.run(["docker", "compose", "-f", compose, "run", "--rm", "--no-deps", "--entrypoint",
                              "python3", "samba", "/fabric/make_bind_dns.py"],
                             capture_output=True, text=True, timeout=300)
        if res.returncode != 0:
            why = (res.stderr or res.stdout)[-300:]
            raise ValidationError(f"BIND's copy of the restored domain's DNS could not be made: {why}")
    pending.pop("directory")
    write_restore_pending(config_dir, pending)
    os.remove(dump)
    return True
