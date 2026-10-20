import datetime
import json
import os

from fabriclib.breakglass.constants import ENTERPRISE_ADMIN, FILE_NAME, FOLDER, RECORD
from fabriclib.common.sudo_owner import sudo_owner

TEXT = """fabric-admin — the Enterprise Admin and break-glass account of {domain}
=======================================================================

user name: {user}
password:  {password}

Written once by fabric ({why}, {when}). fabric keeps this password nowhere else:
not in OpenBao, not in its settings, not in its logs.

Now: copy it into your own safekeeping (a password manager, a sealed envelope),
then delete this file. Until it is gone, the web console and
`sudo fabricctl doctor` remind every administrator.

Use this account only to break glass: everyday work is your own administrator's.
Wrong passwords lock it for a while (3, then 15 minutes, unless its policy was
changed on the host), then it unlocks by itself.
Lost it? On a host with a writable domain controller:
    sudo fabricctl admin reset-break-glass
"""


def write_break_glass_file(password, domain, config_dir, why="setup", owner=None):
    """Purpose: the break-glass password written once to `~/fabric-admin/` of the account that ran sudo (2.1.6.69,
             2.1.6.75): the folder 0700 and the file 0600, both owned by that account, beside the OpenBao recovery
             keys; and where it was written recorded on the host (<config>/break-glass.json: the path and when, never
             the password), so the reminder finds it until it is deleted.
    Inputs:  password — str; domain — the AD domain (the file's heading); config_dir — the install's config folder;
             why — "setup" or "reset" (said in the file and the record); owner — (login, home, uid, gid), default
             sudo_owner().
    Returns: str, the file's path.
    Fails:   OSError when the folder or file cannot be written, chmod-ed or chown-ed, or the record not written.
    Feeds:   setup/create_admin, breakglass/reset_break_glass."""
    login, home, uid, gid = owner or sudo_owner()
    folder = os.path.join(home, FOLDER)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    os.chmod(folder, 0o700)
    os.chown(folder, uid, gid)
    path = os.path.join(folder, FILE_NAME)
    when = datetime.datetime.now().isoformat(timespec="seconds")
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(TEXT.format(domain=domain, user=ENTERPRISE_ADMIN, password=password,
                            why="by setup" if why == "setup" else "by `fabricctl admin reset-break-glass`",
                            when=when))
    os.chmod(tmp, 0o600)
    os.chown(tmp, uid, gid)
    os.replace(tmp, path)
    record = os.path.join(config_dir, RECORD)
    fd = os.open(record + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"path": path, "login": login, "written": when, "by": why}, f)
    os.replace(record + ".new", record)
    return path
