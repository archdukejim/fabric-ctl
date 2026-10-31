import os
import re

from fabriclib.hostaccounts.approvals import load_approvals
from fabriclib.hostaccounts.constants import ADMIN_GROUPS, GROUP, PASSWD, SUDOERS, SUDOERS_DIR
from fabriclib.localadmin.constants import USER as LOCAL_ADMIN
from fabriclib.localadmin.record import load_record

TAG_RE = re.compile(r"^[A-Z_]+:")            # NOPASSWD:, SETENV:, … before a rule's commands


def _table(path):
    """Purpose: a colon-separated system table (/etc/passwd, /etc/group) as rows.
    Inputs:  path — the file.
    Returns: list of lists of str; [] when the file is missing.
    Fails:   OSError other than a missing file.
    Feeds:   list_local_admins."""
    try:
        with open(path) as f:
            return [line.rstrip("\n").split(":") for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return []


def _sudoers_lines(path, folder):
    """Purpose: the sudoers rules sudo reads: the main file, then each file of the drop-in folder sudo reads (not
             ending in ~ and with no dot in its name), continuation lines joined, comments dropped.
    Inputs:  path — /etc/sudoers; folder — /etc/sudoers.d.
    Returns: list of (file, line) tuples.
    Fails:   OSError other than a missing file or folder.
    Feeds:   list_local_admins."""
    files = [path]
    try:
        files += sorted(os.path.join(folder, n) for n in os.listdir(folder) if "." not in n and not n.endswith("~"))
    except FileNotFoundError:
        pass
    out = []
    for name in files:
        try:
            with open(name) as f:
                text = f.read().replace("\\\n", " ")
        except FileNotFoundError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#include", "@include")):
                continue
            line = re.sub(r"(^|\s)#(?!\d).*$", "", line).strip()
            if line:
                out.append((name, line))
    return out


def _grants_all(rest):
    """Purpose: whether a rule's right-hand side (after `hosts =`) grants every command.
    Inputs:  rest — str, e.g. "(ALL:ALL) NOPASSWD: ALL".
    Returns: bool.
    Fails:   never.
    Feeds:   list_local_admins."""
    for spec in rest.split(","):
        spec = re.sub(r"^\s*\([^)]*\)", "", spec).strip()
        while TAG_RE.match(spec):
            spec = spec.split(":", 1)[1].strip()
        if spec == "ALL":
            return True
    return False


def list_local_admins(config_dir, passwd=PASSWD, group=GROUP, sudoers=SUDOERS, sudoers_dir=SUDOERS_DIR):
    """Purpose: every local account with root or administrator rights on this host (2.1.6.78, 2.1.7.15): uid 0 other
             than root, members of sudo, wheel or admin, and accounts a sudoers rule grants ALL commands (by name, by
             a group, by a User_Alias); local accounts only (the passwd file, never the domain's through sssd, so
             fabric-admin's own rule is not one). Each says why it is listed, whether it ran setup, whether the
             Enterprise Admin approved it, and whether OpenBao manages it (the local-admin fabric made, 1.7.1.4.8).
    Inputs:  config_dir — the install's config folder (the record); passwd, group, sudoers, sudoers_dir — the system
             files (tests give their own).
    Returns: list of {"name", "why": [str], "setup": bool, "approved": {"by", "when"} or None, "managed": bool},
             sorted by name.
    Fails:   OSError reading a file (sudoers is root's alone: run as root); ValueError from the record.
    Feeds:   run_host_command (`fabricctl host accounts list`), approve_local_account, local_account_reminders."""
    users = {row[0]: row for row in _table(passwd) if len(row) >= 4}
    groups = {row[0]: row for row in _table(group) if len(row) >= 4}

    def members(name):
        row = groups.get(name)
        if not row:
            return set()
        listed = {m for m in row[3].split(",") if m}
        return listed | {u for u, r in users.items() if r[3] == row[2]}

    why = {}
    for name, row in users.items():
        if row[2] == "0" and name != "root":
            why.setdefault(name, []).append("uid 0")
    for g in ADMIN_GROUPS:
        for name in members(g):
            why.setdefault(name, []).append(f"in the {g} group")
    lines = _sudoers_lines(sudoers, sudoers_dir)
    aliases = {}
    for _, line in lines:
        m = re.match(r"^User_Alias\s+(.*)$", line)
        if m:
            for part in m.group(1).split(":"):
                if "=" in part:
                    alias, who = part.split("=", 1)
                    aliases[alias.strip()] = [w.strip() for w in who.split(",") if w.strip()]
    for file, line in lines:
        if line.startswith(("Defaults", "User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias", "Cmd_Alias")):
            continue
        if "=" not in line or not _grants_all(line.split("=", 1)[1]):
            continue
        who = line.split("=", 1)[0].split()
        if not who:
            continue
        names = set()
        for w in who[0].split(","):
            for x in aliases.get(w, [w]):
                if x == "ALL":
                    names |= set(users)
                elif x.startswith("%:"):
                    names |= members(x[2:])
                elif x.startswith("%"):
                    names |= members(x[1:])
                elif x.startswith("#") and x[1:].isdigit():
                    names |= {u for u, r in users.items() if r[2] == x[1:]}
                else:
                    names.add(x)
        for name in names & set(users):
            if name != "root":
                why.setdefault(name, []).append(f"sudo ALL in {file}")
    record = load_approvals(config_dir)
    managed = load_record(config_dir)["made"]          # OpenBao's local-admin, made by fabric (D6)
    return [{"name": n, "why": sorted(set(w)), "setup": n == record["setup_user"],
             "approved": record["approved"].get(n), "managed": managed and n == LOCAL_ADMIN}
            for n, w in sorted(why.items())]
