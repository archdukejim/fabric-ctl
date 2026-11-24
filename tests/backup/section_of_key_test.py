#!/usr/bin/env python3
"""Every vars.yaml key belongs to one section of a backup (backup/section_of_key, manual 1.3.7.3): pure logic.

    python3 tests/backup/section_of_key_test.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.backup.section_of_key import section_of_key  # noqa: E402

FAILED = 0


def check(name, got, want):
    global FAILED
    FAILED += got != want
    print(("PASS " if got == want else "FAIL ") + name + ("" if got == want else f"  -> {got!r}"))


with open(os.path.join(ROOT, "templates", "vars.yaml.j2")) as f:
    keys = sorted(set(re.findall(r"^([a-z][a-z0-9_]*):", f.read(), re.M)))
errors = []
for key in keys:
    try:
        section_of_key(key)
    except ValueError as exc:
        errors.append(str(exc))
check(f"positive: each of vars.yaml's {len(keys)} keys has exactly one section", errors, [])
for key, want in [("tsig_keys", "dns"), ("dns", "dns"), ("dns_filter_groups", "dns"), ("ca_name", "pki"),
                  ("cert_service_days", "pki"), ("byoc", "pki"), ("ad_realm", "directory"), ("dc_name", "directory"),
                  ("openbao_key_dir", "secrets"), ("signin_kerberos", "signin"), ("dhcp", "dhcp"),
                  ("host_ip", "settings"), ("lan_cidr", "settings"), ("hostname", "settings")]:
    check(f"positive: {key} is {want}'s", section_of_key(key), want)
for key in ("openbao_mem_limit", "dns_server", "postgres_data_dir", "keycloak_data_dir"):
    check(f"negative: {key} looks like another section's but is the host's wiring: settings", section_of_key(key),
          "settings")
check("negative: a key no section names (a new one) is settings'", section_of_key("something_new"), "settings")
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
