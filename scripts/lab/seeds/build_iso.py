"""ISO building with xorriso: a small data ISO from a folder, and a remaster of an installer ISO with replaced files.

Purpose: write the lab's answer media (manual 3.1.5.3) without touching the original ISOs in D:\\os\\AMD64-x86.
Inputs: folders, labels, the original ISO, {path in ISO: local file}.
Returns: nothing; the output ISO exists when it returns.
Fails: CalledProcessError from xorriso (its output is kept in the log next to the output).
Feeds: ubuntu_seed.py, windows_seed.py, proxmox_seed.py.
"""
import os
import shutil
import subprocess


def data_iso(folder, label, out):
    """A Joliet + Rock Ridge ISO of folder's files (NoCloud's CIDATA, Windows' answer CD)."""
    tmp = out + ".part"
    _run(["xorriso", "-as", "mkisofs", "-quiet", "-V", label, "-J", "-joliet-long", "-r",
          "-o", tmp, folder], out)
    os.replace(tmp, out)


def extract(iso, path_in_iso, local):
    _run(["xorriso", "-osirrox", "on", "-indev", iso, "-extract", path_in_iso, local], local)
    os.chmod(local, 0o644)


def remaster(iso, out, files, append=False):
    """A copy of iso with files ({path in ISO: local file}) added or replaced, its boot setup kept as it was.

    append: copy the ISO and add a session to the copy, its boot records kept as they are (what
    proxmox-auto-install-assistant prepare-iso does: `xorriso -boot_image any keep -dev`); Proxmox's ISO needs it,
    its GPT cannot be rebuilt by a replay.
    """
    tmp = out + ".part"
    if os.path.exists(tmp):
        os.remove(tmp)
    if append:
        shutil.copyfile(iso, tmp)
        cmd = ["xorriso", "-boot_image", "any", "keep", "-dev", tmp]
    else:
        cmd = ["xorriso", "-indev", iso, "-outdev", tmp, "-boot_image", "any", "replay"]
    for target, local in sorted(files.items()):
        cmd += ["-map", local, target]
    _run(cmd, out)
    os.replace(tmp, out)


def _run(cmd, near):
    log = near + ".xorriso.log"
    with open(log, "w") as f:
        subprocess.run(cmd, check=True, stdout=f, stderr=subprocess.STDOUT)
