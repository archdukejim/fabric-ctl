#!/usr/bin/env python3
"""Every suite of tests/run-all.sh runs in CI (decision 2.1.1.37): deploy and zones never did, unseen, until 2026-11-05, and a
red deploy went in that way (2.3.1.53). The suites of suites.yml's matrix, with lint in lint.yml and the sandbox in its own job.

    python3 tests/docs/check_ci_suites.py
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SEPARATE = {"lint": ("lint.yml", "tests/lint/run.sh"), "sandbox": ("suites.yml", "tests/run-all.sh sandbox")}


def local_suites(text):
    """Purpose: the suites run-all.sh knows, from its case branches.
    Inputs:  text — str, run-all.sh.
    Returns: set of str.
    Fails:   never.
    Feeds:   main."""
    return set(re.findall(r"^\s+([a-z0-9]+)\)\s", text, re.M))


def matrix_suites(text):
    """Purpose: the suites of a workflow's matrix; "render nginx", one job, is two.
    Inputs:  text — str, suites.yml.
    Returns: set of str.
    Fails:   never.
    Feeds:   main."""
    found = re.search(r"suite:\s*\[(.*?)\]", text, re.S)
    return set(re.findall(r"[a-z0-9]+", found.group(1))) if found else set()


def main():
    """Purpose: compare them; first prove the check can fail.
    Inputs:  none.
    Returns: 0 when every suite runs in CI, 1 with those that do not.
    Fails:   OSError reading the files.
    Feeds:   tests/docs/run.py."""
    assert local_suites("        deploy)   run deploy   x\n        zones)    run zones    y\n") == {"deploy", "zones"}
    assert matrix_suites('suite: [docs, "render nginx",\n   zone]') == {"docs", "render", "nginx", "zone"}
    assert not matrix_suites("no matrix here")
    assert local_suites("        deploy)   run deploy   x\n") - matrix_suites("suite: [docs]") == {"deploy"}

    def read(*path):
        with open(os.path.join(REPO, *path), encoding="utf-8") as f:
            return f.read()

    missing = local_suites(read("tests", "run-all.sh")) - matrix_suites(read(".github", "workflows", "suites.yml"))
    for suite, (workflow, command) in SEPARATE.items():
        if command in read(".github", "workflows", workflow):
            missing.discard(suite)
    for suite in sorted(missing):
        print(f"    {suite}: in tests/run-all.sh, and CI never runs it")
    print(f"    {len(missing)} suite(s) CI never runs")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
