#!/usr/bin/env python3
"""one_off_labels (manual 1.2.4.6): a throwaway container's labels put it in no unit's Compose project. Pure: the
real case (an image with Compose's labels, a project left running by Kea's check) is in tests/kea/run.py."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.common.one_off_labels import one_off_labels  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


args = one_off_labels()
pairs = dict(a.split("=", 1) for a in args[1::2])
check("every value follows a --label", args[0::2] == ["--label"] * (len(args) // 2), args)
check("the project and the service are set over an image's own (Compose's labels a built image carries)",
      pairs.get("com.docker.compose.project") == "fabric-one-off"
      and pairs.get("com.docker.compose.service") == "one-off", pairs)
UNITS = {"kea", "stepca", "webui", "bind9", "samba", "keycloak", "postgres", "nginx", "openbao", "freeradius",
         "resolver", "dnsfilter", "fluentbit"}
check("negative: the project is none a fabric unit runs", pairs["com.docker.compose.project"] not in UNITS, pairs)
print(f"\n{3 - FAILED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
