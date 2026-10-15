#!/usr/bin/env python3
"""Every entry point has a positive and a negative test, or is a listed gap (decisions 2.1.1.38, 2.1.1.46; manual
3.1.2.5). Fails when the inventory is stale, a marker names nothing, an entry point lacks a case and is not listed in
tests/entrypoints-gaps.txt, or a listed gap is now covered or names nothing (the list only shrinks).

    python3 tests/docs/check_entrypoints.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                "scripts", "docs"))
import entrypoints  # noqa: E402


def listed_gaps():
    """Purpose: the ratchet's list: tests/entrypoints-gaps.txt, one `<id> +` or `<id> -` per line (# comments).
    Inputs:  none.
    Returns: set of lines (empty when the file does not exist).
    Fails:   never.
    Feeds:   main."""
    try:
        text = entrypoints._read(entrypoints.GAPS)
    except OSError:
        return set()
    return {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}


def main():
    """Purpose: run the check, print each problem.
    Inputs:  none.
    Returns: exit status: 0 when nothing is wrong, 1 otherwise.
    Fails:   as entrypoints.collect.
    Feeds:   tests/docs/run.py."""
    problems = []
    if entrypoints.main(["--check"]) != 0:
        problems.append("the inventory is stale")
    found = entrypoints.collect()
    _covered, named = entrypoints.markers()
    problems += [f"{where}: the marker names {ident}, which is no entry point" for where, ident in named
                 if ident not in found]
    actual = set(entrypoints.gaps(found))
    listed = listed_gaps()
    problems += [f"{gap}: no test, and not in {entrypoints.GAPS}" for gap in sorted(actual - listed)]
    for gap in sorted(listed - actual):
        ident = gap.rsplit(" ", 1)[0]
        why = "names no entry point" if ident not in found else "is covered now: remove it from the list"
        problems.append(f"{gap}: {why} ({entrypoints.GAPS} only shrinks)")
    for line in problems:
        print(f"  {line}")
    print(f"{len(found)} entry points, {len(actual)} listed gaps" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
