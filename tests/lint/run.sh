#!/bin/bash
# The lint suite (decision 2.1.1.15, manual 3.1.2): ruff for Python, shellcheck for shell scripts, every Python file
# parsed by the oldest supported Python (3.10, Ubuntu 22.04: 2.1.1.43), and no prompt outside ask() (1.1.5.6). All run from their published images, pinned by
# digest (nothing is installed on the host).
#   sudo tests/run-all.sh lint
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RUFF="ghcr.io/astral-sh/ruff:0.13.3@sha256:97b6a4512a9f50f50bd10ce64363b35c1f384d6615ceb6b6b9b0d05654908a55"
SHELLCHECK="koalaman/shellcheck:v0.11.0@sha256:bb596a0d169b85ddd81d8b6d3a2ff6d5baf5fca10b97f575ebc647c3dff62b3d"
PY310="python:3.10-slim@sha256:6ff506466f8b1e981719b468cc0023b8ef000b983cdec0eafe119d01f379e31d"
PASS=0; FAIL=0
check() { if eval "$2"; then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
cd "$REPO" || exit 1

# Purpose: list the repository's shell scripts under the given paths (*.sh, and extension-less files whose
#          first line is a shell shebang).
# Inputs:  $@ — repository paths (git pathspecs).
# Returns: the paths on stdout, one per line.
# Fails:   never (git errors print nothing).
# Feeds:   the shellcheck checks below.
shell_files() {
    git ls-files --cached --others --exclude-standard -- "$@" | while read -r f; do
        case "$f" in
            *.sh) echo "$f" ;;
            *.*) ;;
            *) head -c 40 "$f" 2>/dev/null | grep -qE '^#!(/usr)?/bin/(env )?(ba)?sh' && echo "$f" ;;
        esac
    done
}

# pulled first, so a check's output is only the tool's findings (a pull reports its progress on stderr)
for image in "$RUFF" "$SHELLCHECK" "$PY310"; do docker pull -q "$image" >/dev/null || { echo "FAIL cannot pull $image"; exit 1; }; done

out=$(docker run --rm -v "$REPO:/io" -w /io "$RUFF" check src scripts tests 2>&1); rc=$?
echo "$out" | tail -15 | sed 's/^/    /'
check "ruff: no findings in src/, scripts/ and tests/ (pyproject.toml)" "[ $rc -eq 0 ]"

# ruff parses with the newest grammar whatever its target: only a real 3.10 refuses 3.12-only syntax (2.1.1.43)
out=$(docker run --rm -v "$REPO:/io:ro" -w /io "$PY310" python3 tests/lint/parse_py.py src scripts 2>&1); rc=$?
echo "$out" | tail -15 | sed 's/^/    /'
check "Python 3.10 parses every file in src/ and scripts/ (the oldest supported host, Ubuntu 22.04)" "[ $rc -eq 0 ]"

# every question goes through fabriclib/common/ask.py with a stable ID (manual 1.1.5.6): no input()/getpass() elsewhere
out=$(docker run --rm -v "$REPO:/io:ro" -w /io "$PY310" python3 tests/lint/no_bare_prompts.py src 2>&1); rc=$?
echo "$out" | tail -15 | sed 's/^/    /'
check "no input() or getpass() in src/ outside common/ask.py; every ask() has a literal <area>.<name> ID" "[ $rc -eq 0 ]"

mapfile -t product < <(shell_files src packaging scripts)
out=$(docker run --rm -v "$REPO:/mnt" -w /mnt "$SHELLCHECK" -S warning "${product[@]}" 2>&1); rc=$?
echo "$out" | tail -15 | sed 's/^/    /'
check "shellcheck: no warnings in the product's ${#product[@]} shell scripts" "[ $rc -eq 0 ]"

# the suites' checks run as strings through eval, which shellcheck cannot follow: variables they read look
# unused (SC2034) and per-command assignments look unseen (SC2097/SC2098)
mapfile -t suites < <(shell_files tests)
out=$(docker run --rm -v "$REPO:/mnt" -w /mnt "$SHELLCHECK" -S warning -e SC2034,SC2097,SC2098 "${suites[@]}" 2>&1); rc=$?
echo "$out" | tail -15 | sed 's/^/    /'
check "shellcheck: no warnings in the tests' ${#suites[@]} shell scripts (eval-only findings excepted)" "[ $rc -eq 0 ]"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
