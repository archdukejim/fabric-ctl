#!/usr/bin/env python3
"""The listener's user number is nobody's (manual 1.3.6.7, decision 2.1.8.61): an account, a group or a process holding it
is named and refused. This host's real accounts, and a /proc of the test's own for the processes.
    python3 tests/setup/site/site_account_test.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import check, finish  # noqa: E402

from fabriclib.setup.errors import SetupError  # noqa: E402
from fabriclib.setup.site.constants import SITE_ID  # noqa: E402
from fabriclib.setup.site.site_account import site_account  # noqa: E402


def fake_proc(*uids):
    """A /proc with one process per uid (its status's Uid line), and a folder that is no process."""
    top = tempfile.mkdtemp(prefix="fabric-proc-")
    os.makedirs(os.path.join(top, "sys"))
    for pid, uid in enumerate(uids, start=100):
        os.makedirs(os.path.join(top, str(pid)))
        with open(os.path.join(top, str(pid), "status"), "w") as f:
            f.write(f"Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    os.makedirs(os.path.join(top, "999"))     # a process that ended while it was read: no status
    return top


def refused(number, proc):
    try:
        site_account(number, proc)
    except SetupError as e:
        return str(e)
    return ""


free = next(n for n in range(64000, 65000) if not refused(n, fake_proc()))
check("a number nobody holds: accepted", site_account(free, fake_proc(0, 1000)) == free)
why = refused(0, fake_proc())
check("a number an account holds: refused, naming it and offering --terminal",
      "the account root" in why and "the group root" in why and "--terminal" in why and "Nothing was changed" in why, why)
why = refused(free, fake_proc(1000, free))
check("a number a running process holds: refused, naming the process", "process 101" in why and "account" not in why, why)
check("the product's number is 649, the top of fabric's band", SITE_ID == 649)

sys.exit(finish("site_account_test"))
