#!/bin/bash
# -----------------------------------------------------------------------
# tests/host/upgrade.sh's FROM (2.1.1.61): the floor 0.8.0 and later releases are taken; an older FROM (0.7.x has no
# upgrade into 0.8.0, 2.1.1.60) or one that is not a version is refused with why, before any host is reached
# (TARGET names a host that does not exist: a refusal that tried it would fail differently). Pure, in the consent
# suite.
#   bash tests/host/upgrade_from_test.sh
# -----------------------------------------------------------------------
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PASS=0; FAIL=0
check() { if (set +o pipefail; eval "$2"); then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
run() {   # FROM [FROM_CHECK_ONLY] -> output, then the exit code on the last line
    env TARGET=nobody@upgrade-test.invalid HOST_IP=192.0.2.1 LAN_CIDR=192.0.2.0/24 GATEWAY=192.0.2.254 \
        FROM="$1" TO_SUITE=testing ${2:+FROM_CHECK_ONLY=1} KEY=/nonexistent bash "$HERE/upgrade.sh" 2>&1
    echo "exit=$?"
}
for from in 0.8.0 0.8.1 0.9.0 1.0.0; do
    out=$(run "$from" 1)
    check "FROM=$from is taken (at or above the floor 0.8.0)" \
        "grep -q 'at or above the floor 0.8.0' <<<\"\$out\" && grep -q 'exit=0' <<<\"\$out\""
done
for from in 0.7.1 0.7.2 0.6.4; do
    out=$(run "$from")
    check "FROM=$from is refused, saying it is older than the floor and that 0.7.x moves (3.3.5); no host reached" \
        "grep -q 'older than the upgrade floor 0.8.0' <<<\"\$out\" && grep -q 'manual 3.3.5' <<<\"\$out\" \
         && grep -q 'exit=2' <<<\"\$out\" && ! grep -qiE 'ssh|wipe' <<<\"\$out\""
done
for from in latest 0.8 v0.8.0; do
    out=$(run "$from")
    check "FROM=$from is refused: not a release version" \
        "grep -q 'is not a release version' <<<\"\$out\" && grep -q 'exit=2' <<<\"\$out\""
done
echo; echo "$PASS passed, $FAIL failed"
exit $FAIL
