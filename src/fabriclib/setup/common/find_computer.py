import re
import subprocess

from fabriclib.setup.errors import SetupError

SAM = "/data/private/sam.ldb"           # the DC's database inside the samba container
NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,15}$")


def find_computer(account, container="samba"):
    """Purpose: whether the domain has a computer account of this name, anywhere (any site, any OU), and where:
             read inside the DC as the system (its own database, no credentials).
    Inputs:  account — the account's name without its $ ("FAB1"; 1-15 letters, digits, dashes); container — the
             DC's container.
    Returns: {"dn": str, "description": str} or None when there is none.
    Fails:   SetupError for a name that is not a computer name, or when the DC cannot be read (not running).
    Feeds:   setup/join_host_domain."""
    if not NAME_RE.match(account or ""):
        raise SetupError(f"not a computer name: {account!r}")
    res = subprocess.run(["docker", "exec", container, "ldbsearch", "-H", SAM,
                          f"(&(objectCategory=computer)(sAMAccountName={account}$))", "dn", "description"],
                         capture_output=True, text=True)
    if res.returncode != 0:
        raise SetupError(f"the domain controller's directory could not be read (is the samba container running?): "
                         f"{(res.stderr or res.stdout).strip()[-400:]}")
    found = {}
    for line in res.stdout.splitlines():
        key, _, value = line.partition(": ")
        if key in ("dn", "description") and key not in found:
            found[key] = value.strip()
    return {"dn": found["dn"], "description": found.get("description", "")} if "dn" in found else None
