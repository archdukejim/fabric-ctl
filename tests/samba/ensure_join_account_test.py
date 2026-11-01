"""The join account's Domain Admins membership at a site's DC, its pure part (2.3.6.27): a sibling's join account
whose deletion is still replicating is waited out; any other refusal is not. Samba's ldb is a stand-in; the real DCs'
run is tests/samba/site_join.py.
    python3 tests/samba/ensure_join_account_test.py"""
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "containers", "samba"))


class LdbError(Exception):
    """ldb.LdbError's stand-in: args (code, text)."""


sys.modules["ldb"] = types.SimpleNamespace(LdbError=LdbError, ERR_NO_SUCH_OBJECT=32, ERR_INSUFFICIENT_ACCESS_RIGHTS=50)
import ensure_join_account as m  # noqa: E402

FAILED = 0
STALE = "No such Base DN: CN=fabric-join-edge,OU=people,DC=ad,DC=test"


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


class Samdb:
    """Refuses the first `fails` adds with the given error, then takes them."""

    def __init__(self, fails, error):
        self.fails, self.error, self.calls = fails, error, []

    def add_remove_group_members(self, group, members, add_members_operation=True):
        self.calls.append((group, tuple(members), add_members_operation))
        if len(self.calls) <= self.fails:
            raise self.error


class Clock:
    """time.monotonic and time.sleep together: sleeping moves the clock."""

    def __init__(self):
        self.now, self.slept = 0.0, []

    def clock(self):
        return self.now

    def sleep(self, s):
        self.slept.append(s)
        self.now += s


def run(db, settle=60):
    c = Clock()
    try:
        m._add_to_domain_admins(db, "fabric-join-lab2", settle=settle, pause=2.0, sleep=c.sleep, clock=c.clock)
        return "", c
    except LdbError as e:
        return str(e.args[1] if len(e.args) > 1 else e), c


db = Samdb(2, LdbError(32, STALE))
err, c = run(db)
check("a sibling's join account still replicating its deletion is waited out, then the account is added",
      err == "" and len(db.calls) == 3 and db.calls[-1] == ("Domain Admins", ("fabric-join-lab2",), True)
      and c.slept == [2.0, 2.0], (err, db.calls, c.slept))
db = Samdb(99, LdbError(32, STALE))
err, c = run(db, settle=10)
check("negative: a deletion that never replicates is refused after the wait, saying so (no endless loop)",
      "did not replicate within 10 s" in err and STALE in err and c.now >= 10 and len(db.calls) <= 7, (err, c.now))
db = Samdb(1, LdbError(32, "No such Base DN: CN=fabric-join-lab2,OU=people,DC=ad,DC=test"))
err, c = run(db)
check("negative: the account itself missing is refused at once, not waited for",
      "CN=fabric-join-lab2," in err and len(db.calls) == 1 and c.slept == [], (err, db.calls))
db = Samdb(1, LdbError(50, "insufficient access"))
err, c = run(db)
check("negative: any other refusal is refused at once", err == "insufficient access" and len(db.calls) == 1, err)
print(f"\n{4 - FAILED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
