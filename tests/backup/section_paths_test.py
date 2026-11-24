#!/usr/bin/env python3
"""What each section of a backup packs (backup/section_paths, manual 1.3.7.3): a temporary install root, no services.

    python3 tests/backup/section_paths_test.py
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.backup.section_paths import section_paths  # noqa: E402
from fabriclib.backup.sections import ORDER, SECTIONS  # noqa: E402
from fabriclib.setup.uninstall import DIRS  # noqa: E402

FAILED = 0


def check(name, got, want):
    global FAILED
    FAILED += got != want
    print(("PASS " if got == want else "FAIL ") + name + ("" if got == want else f"  -> {got!r}"))


tmp = tempfile.mkdtemp()
base = os.path.join(tmp, "opt", "fabric")
outside = os.path.join(tmp, "srv", "openbao-key")
for rel in ("bind9/data", "bind9/ssl", "stepca/data", "samba/data", "openbao/data", "openbao/certs", "fabric/config"):
    os.makedirs(os.path.join(base, *rel.split("/")))
os.makedirs(outside)
vars_ = {"openbao_key_dir": outside, "postgres_data_dir": os.path.join(base, "postgres", "data")}
check("positive: dns packs bind9 without pki's bind9/ssl",
      section_paths("dns", base, vars_), [(os.path.join(base, "bind9"), [os.path.join(base, "bind9", "ssl")])])
check("positive: pki packs stepca and bind9/ssl, openbao/certs",
      [p for p, _ in section_paths("pki", base, vars_)],
      [os.path.join(base, "stepca"), os.path.join(base, "bind9", "ssl"), os.path.join(base, "openbao", "certs")])
check("positive: secrets packs openbao (not its certs) and the key folder outside the root",
      section_paths("secrets", base, vars_),
      [(os.path.join(base, "openbao"), [os.path.join(base, "openbao", "certs")]), (outside, [])])
check("negative: a section whose folders are not there packs nothing (DHCP not installed)",
      section_paths("dhcp", base, vars_), [])
check("negative: a data folder set inside the root is not packed twice as outside",
      [p for p, _ in section_paths("signin", base, vars_)], [])
claimed = {rel.split("/")[0] for name in ORDER for rel in SECTIONS[name]["dirs"]}
check("positive: every folder fabric installs (uninstall.DIRS) is in a section", sorted(set(DIRS) - claimed), [])
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
