#!/usr/bin/env python3
"""No script of the certificates page is fetched by plain HTTP (decisions 2.1.1.85, 2.1.1.87), the join's or an installer's:
fails if a page, a template, the code or the manual still says so. A script fetched over HTTP and run as root cannot be vouched for by a fingerprint it checks itself.

Left out: Volume 2's decisions and notes (they tell what was, and why it changed), the function reference's generated
text, and tests/ (the floor's own join, a released version's, is still done its way).

    python3 tests/docs/check_join_fetch.py
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOPS = ("README.md", "docs", "templates", "src", "static", "config", "examples", "packaging")
SKIP = ("docs/volume_2_engineering_decisions/",)
# on one line: http:// and a script's name after it, a template's {{ name }} included; a shell variable's too (BASE_URL)
FETCH = re.compile(r"(http://[^\n]{0,80}?|\$BASE_URL)/(join-linux|install-[^\n/\"']*?)\.sh")
TEXT = (".md", ".j2", ".py", ".html", ".sh", ".txt", ".yaml", ".yml", ".js")


def found_in(text):
    """Purpose: the lines of a text that fetch the script by HTTP.
    Inputs:  text — str.
    Returns: [(line number, line)].
    Fails:   never.
    Feeds:   main."""
    return [(n, line) for n, line in enumerate(text.splitlines(), 1) if FETCH.search(line)]


def main():
    """Purpose: check every file; first prove the check can fail.
    Inputs:  none.
    Returns: 0 clean, 1 with what was found.
    Fails:   never.
    Feeds:   tests/docs/run.py."""
    for bad in ("wget -nv http://info.lab.test/certs/join-linux.sh", "http://{{ hostname_stepca }}/certs/join-linux.sh",
                "curl -fsS http://10.0.0.1/certs/join-linux.sh -o j.sh", "wget -nv -O- http://ca.lab.test/certs/install-all-lan.sh | bash",
                "http://{{ hostname_stepca }}/certs/install-certs-{{ domain_file }}.sh", 'wget -nv -O- "$BASE_URL/install-certs-$DOMAIN.sh" | bash'):
        assert found_in(bad), bad
    assert not found_in("curl --cacert r.crt --capath . https://h.lab.test/certs/join-linux.sh")
    assert not found_in("https://h.lab.test/certs/install-certs-lan.sh") and not found_in("http://ca.lab.test/certs/root-ca.crt")
    problems = []
    for top in TOPS:
        path = os.path.join(REPO, top)
        files = [path] if os.path.isfile(path) else [os.path.join(d, f) for d, _s, fs in os.walk(path) for f in fs]
        for name in files:
            rel = os.path.relpath(name, REPO).replace(os.sep, "/")
            if rel.startswith(SKIP) or not rel.endswith(TEXT) or re.search(r"/1\.17\.\d+-", rel):
                continue
            with open(name, encoding="utf-8", errors="replace") as f:
                problems += [f"{rel}:{n}: {line.strip()[:120]}" for n, line in found_in(f.read())]
    for problem in problems:
        print(f"    {problem}")
    print(f"    {len(problems)} place(s) fetch a script by HTTP (2.1.1.85, 2.1.1.87)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
