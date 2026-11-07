"""The sizing fill in one batch, inside a test install's DC (manual 1.8.8.8, 2.3.8.5.1): the same people, computers and
groups as size_fill.py, made by the DC's own functions (create_person, create_machine, create_group: the code
fabric-agent's operations run), but in one process over one local database, so 5,000 people take minutes, not a day.
Re-runs top up. Only for a test install: nothing is audited, and the people's passwords are random and kept nowhere.

    docker exec -i samba python3 - <people> <site> <dc> [<users gid>] < size_fill_dc.py
        (the DC's /fabric is read-only, so size_measure.sh gives it on standard input; prints "made <people> people, <machines> computers,
        <groups> groups in <s> s")
"""
import secrets
import sys
import time

sys.path.insert(0, "/fabric")
import ldb  # noqa: E402
from create_group import create_group  # noqa: E402
from create_machine import create_machine  # noqa: E402
from create_person import create_person  # noqa: E402
from open_samdb import open_samdb  # noqa: E402

CONF = "/data/etc/smb.conf"


def _password():
    """A one-time password the domain's policy takes (every class of character); shown and kept nowhere."""
    return secrets.token_urlsafe(18) + "aA1!"


def _have(samdb, account):
    """Whether an account of that sAMAccountName is in the domain already (a re-run tops up)."""
    return bool(samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                             expression=f"(sAMAccountName={ldb.binary_encode(account)})", attrs=["dn"]))


def main():
    if len(sys.argv) not in (4, 5) or not sys.argv[1].isdigit():
        sys.exit(__doc__)
    people, site, dc = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    gid = int(sys.argv[4]) if len(sys.argv) == 5 else 5000
    samdb, lp = open_samdb(CONF)
    groups = max(1, people // 10)
    start, count = time.time(), {"people": 0, "machines": 0, "groups": 0}
    for g in range(1, groups + 1):
        if not _have(samdb, f"szg{g:03d}"):
            create_group(samdb, lp, site, f"szg{g:03d}", "sizing test", dc=dc)
            count["groups"] += 1
    for n in range(1, people + 1):
        uid = f"sz{n:04d}"
        if not _have(samdb, uid):
            create_person(samdb, lp, site, uid, "Size", f"Test {n}", f"{uid}@size.test", _password(), gid, "/home",
                          "/bin/bash", dc=dc)
            count["people"] += 1
            samdb.add_remove_group_members(f"szg{(n - 1) % groups + 1:03d}", [uid], add_members_operation=True)
        if n % 2 == 0 and not _have(samdb, f"SZM{n // 2:04d}$"):
            create_machine(samdb, lp, site, f"szm{n // 2:04d}", _password(), type="server" if n % 4 == 0 else "desktop")
            count["machines"] += 1
        if n % 500 == 0:
            print(f"{n} people ({time.time() - start:.0f} s)", flush=True)
    print(f"made {count['people']} people, {count['machines']} computers, {count['groups']} groups in "
          f"{time.time() - start:.0f} s")


if __name__ == "__main__":
    main()
