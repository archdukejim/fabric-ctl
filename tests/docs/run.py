#!/usr/bin/env python3
"""The docs suite: the documentation says what the code does.

  - every product function has a structured docstring (check_docstrings.py)
  - the function reference (manual 1.17) is what those docstrings say (scripts/docs/gen_lib_doc.py --check)
  - docs and code agree on settings, commands, routes, permissions, suites,
    setup steps, READMEs and links (check_consistency.py)
  - every entry point has a positive and a negative test, or is a listed gap (check_entrypoints.py)
  - every file in the repository has been reviewed (scripts/docs/review_ledger.py)

    python3 tests/docs/run.py        (no Docker, no root)
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "scripts", "docs")   # the generator and the ledger
STEPS = [("every function has a structured docstring", [os.path.join(HERE, "check_docstrings.py"), "--summary"]),
         ("the function reference (manual 1.17) matches the code", [os.path.join(TOOLS, "gen_lib_doc.py"), "--check"]),
         ("docs and code agree", [os.path.join(HERE, "check_consistency.py")]),
         ("every entry point is tested both ways, or a listed gap", [os.path.join(HERE, "check_entrypoints.py")]),
         ("every file has been reviewed", [os.path.join(TOOLS, "review_ledger.py")])]


def main():
    """Purpose: run the five checks and report each as PASS/FAIL.
    Inputs:  none.
    Returns: exit status: 0 all passed, 1 any failed.
    Fails:   never raises; a check that crashes counts as FAIL (its output is shown).
    Feeds:   tests/run-all.sh (suite `docs`)."""
    failed = 0
    for name, cmd in STEPS:
        res = subprocess.run([sys.executable, *cmd], cwd=HERE,
                             capture_output=True, text=True)
        ok = res.returncode == 0
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'} {name}")
        if not ok:
            print("    " + "\n    ".join((res.stdout + res.stderr).strip().splitlines()[-40:]))
    print(f"\n{'all passed' if not failed else 'FAILED'} ({failed} failures)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
