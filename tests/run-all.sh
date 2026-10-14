#!/bin/bash
# -----------------------------------------------------------------------
# Run fabric's test suites against real containers.
#
#   sudo tests/run-all.sh [suite ...]      suites: docs lint deploy consent render nginx zone zones webui pki federation resolver ntp openbao fluentbit kea ipam freeradius samba keycloak hardening images
#   sudo tests/run-all.sh sandbox          opt-in: full install in a systemd + Docker sandbox (about 30 min)
#
# Needs: Linux (amd64 or arm64), Docker with buildx, python3 with yaml +
# jinja2, openssl, curl, setpriv. Runs as root (chown to service uids,
# SO_PEERCRED checks). Output and scratch data: $FABRIC_TEST_OUT
# (default /tmp/fabric-tests).
# -----------------------------------------------------------------------
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export FABRIC_TEST_OUT="${FABRIC_TEST_OUT:-/tmp/fabric-tests}"
SUITES=("$@")
[ ${#SUITES[@]} -eq 0 ] && SUITES=(docs lint deploy consent render nginx zone zones webui pki federation resolver ntp openbao fluentbit kea ipam freeradius samba keycloak hardening images)

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 2; }
rm -rf "$FABRIC_TEST_OUT"; mkdir -p "$FABRIC_TEST_OUT"
echo "fabric tests on $(uname -m), output in $FABRIC_TEST_OUT"

declare -A RESULT
run() {  # name command...
    local name="$1"; shift
    echo; echo "=== $name"
    local log="$FABRIC_TEST_OUT/$name.log"
    "$@" 2>&1 | tee "$log"
    local rc=${PIPESTATUS[0]}
    if [ "$rc" -eq 0 ] && ! grep -qE '^FAIL' "$log"; then RESULT[$name]=PASS; else RESULT[$name]=FAIL; fi
}

for s in "${SUITES[@]}"; do
    case "$s" in
        docs)     run docs     python3 "$HERE/docs/run.py" ;;
        lint)     run lint     bash "$HERE/lint/run.sh" ;;
        deploy)   run deploy   bash -c "python3 \"$HERE/deploy/restart_changed_test.py\" && python3 \"$HERE/deploy/check_service_settings_test.py\"" ;;
        consent)  run consent  bash -c "python3 \"$HERE/consent/run.py\" && python3 \"$HERE/common/ask.py\" && python3 \"$HERE/samba/writable_server_test.py\" && python3 \"$HERE/samba/id_layout_test.py\" && python3 \"$HERE/samba/ensure_schema_test.py\"" ;;
        render)   run render   python3 "$HERE/render.py" "$FABRIC_TEST_OUT/rendered" ;;
        nginx)    run nginx    bash "$HERE/nginx_check.sh" "$FABRIC_TEST_OUT/rendered" ;;
        zone)     run zone     python3 "$HERE/zone_test.py" ;;
        zones)    run zones    python3 "$HERE/zones/run.py" ;;
        webui)    run webui    bash -c "python3 \"$HERE/webui/test_container.py\" && python3 \"$HERE/webui/test_devserver.py\"" ;;
        pki)      run pki      python3 "$HERE/pki/run.py" ;;
        federation) run federation python3 "$HERE/federation/run.py" ;;
        resolver) run resolver bash -c "python3 \"$HERE/resolver/run.py\" && python3 \"$HERE/resolver/groups.py\" && python3 \"$HERE/resolver/querylog.py\" && python3 \"$HERE/resolver/console.py\"" ;;
        ntp)      run ntp      python3 "$HERE/ntp/run.py" ;;
        openbao)  run openbao  bash -c "python3 \"$HERE/openbao/run.py\" && python3 \"$HERE/openbao/db_rotation.py\"" ;;
        fluentbit) run fluentbit python3 "$HERE/fluentbit/run.py" ;;
        kea) run kea bash -c "python3 \"$HERE/kea/run.py\" && python3 \"$HERE/kea/scan.py\" && python3 \"$HERE/kea/relay.py\"" ;;
        ipam)     run ipam     bash -c "python3 \"$HERE/ipam/run.py\" && python3 \"$HERE/ipam/networks.py\" && python3 \"$HERE/ipam/scan.py\" && python3 \"$HERE/ipam/options.py\" && python3 \"$HERE/ipam/scan_trigger.py\" && python3 \"$HERE/ipam/sync.py\"" ;;
        freeradius) run freeradius python3 "$HERE/freeradius/run.py" ;;
        samba)    run samba    bash -c "python3 \"$HERE/samba/run.py\" && python3 \"$HERE/samba/dc.py\" && python3 \"$HERE/samba/devices.py\" && python3 \"$HERE/samba/linux_join.py\" && python3 \"$HERE/samba/gpo.py\" && python3 \"$HERE/samba/logon.py\" && python3 \"$HERE/samba/hostgroups.py\" && python3 \"$HERE/samba/site_join.py\" && python3 \"$HERE/samba/ipam.py\" && python3 \"$HERE/samba/ipam_two_site.py\"" ;;
        keycloak) run keycloak python3 "$HERE/keycloak/run.py" ;;
        hardening) run hardening bash "$HERE/hardening/run.sh" ;;
        images)   run images   bash "$HERE/images/run.sh" ;;
        sandbox)  run sandbox  bash "$HERE/sandbox/run.sh" ;;
        *) echo "unknown suite: $s" >&2; exit 2 ;;
    esac
done

echo; echo "=== summary ($(uname -m))"
fail=0
for s in "${SUITES[@]}"; do
    printf '  %-9s %s\n' "$s" "${RESULT[$s]}"
    [ "${RESULT[$s]}" = PASS ] || fail=1
done
exit $fail
