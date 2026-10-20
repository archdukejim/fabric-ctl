#!/bin/bash
# -----------------------------------------------------------------------
# The release's move test (decisions 2.1.1.60, 2.1.1.61; manual 3.3.5), replacing the upgrade test from 0.7.1:
# in a disposable systemd + Docker sandbox (the sandbox suite's image, its own name, network and Docker volume),
#   the FROM release (0.7.1) built from its tag with its own packaging -> apt install -> its own setup
#   -> snapshot (move_state.py) and its /opt/fabric/config/vars.yaml copied out
#   -> 3.3.5.4: uninstall with an export -> this checkout's package installed -> setup --file <that vars.yaml>
#   -> the same zones, records, TSIG keys' rights and parts; a new CA and new TSIG secrets; doctor.
#
#   sudo tests/sandbox/move.sh            (FROM=0.7.1 by default; KEEP=1 leaves the sandbox running)
#
# Shares the sandbox suite's lock: never runs beside it. Needs privileged Docker and git (the FROM tag).
# -----------------------------------------------------------------------
set -uo pipefail
exec 9>/tmp/fabric-sandbox-suite.lock
flock -n 9 || { echo "another sandbox run is active; refusing to start" >&2; exit 2; }
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
FROM="${FROM:-0.7.1}"
OUT="${FABRIC_TEST_OUT:-/tmp/fabric-tests}/move"
NAME=fabric-move
NET=fabric-move-net
VOL=fabric-move-docker
SUBNET=10.78.0.0/24
IP=10.78.0.10
BIND_PORT=5053                      # dns_filter: bind moves BIND off 53, in both releases
PASS=0; FAIL=0
check() { if (set +o pipefail; eval "$2"); then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
in_box() { docker exec "$NAME" bash -lc "$*"; }
cleanup() {
    [ -n "${KEEP:-}" ] && { echo "(kept: docker exec -it $NAME bash)"; return; }
    docker rm -f "$NAME" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; docker volume rm "$VOL" >/dev/null 2>&1
}
docker rm -f "$NAME" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; docker volume rm "$VOL" >/dev/null 2>&1
rm -rf "$OUT"; mkdir -p "$OUT"
trap cleanup EXIT

echo "--- the packages: $FROM from its tag, built by its own packaging; the candidate from this checkout"
git -c safe.directory="*" clone -q --shared --no-checkout "$REPO" "$OUT/from-src" && git -C "$OUT/from-src" checkout -q "v$FROM" \
    || { echo "FAIL tag v$FROM"; exit 1; }
FROM_DEB=$(OUT="$OUT/dist-from" bash "$OUT/from-src/packaging/deb/build-deb.sh") || { echo "FAIL $FROM's package"; exit 1; }
TO_DEB=$(OUT="$OUT/dist" bash "$REPO/packaging/deb/build-deb.sh") || { echo "FAIL the candidate's package"; exit 1; }
check "$FROM's package is version $FROM" "[ \"\$(basename '$FROM_DEB')\" = fabricctl_${FROM}_all.deb ]"

docker build -q -t fabric/sandbox:local "$REPO/tests/sandbox" >/dev/null || { echo "FAIL sandbox image"; exit 1; }
docker network create --subnet "$SUBNET" --gateway 10.78.0.1 "$NET" >/dev/null
# cgroupns=private, no host cgroup mount: as the sandbox suite (its systemd must never see the host's cgroup tree)
docker run -d --name "$NAME" --hostname fabric-sbx --privileged --cgroupns=private -v "$VOL:/var/lib/docker" \
  --tmpfs /run --tmpfs /run/lock --network "$NET" --ip "$IP" fabric/sandbox:local >/dev/null
for _ in $(seq 1 30); do in_box 'systemctl is-system-running 2>/dev/null' | grep -qE 'running|degraded' && break; sleep 2; done
in_box 'mkdir -p /etc/docker && echo "{\"features\": {\"containerd-snapshotter\": false}, \"storage-driver\": \"overlay2\"}" > /etc/docker/daemon.json'
docker cp "$FROM_DEB" "$NAME:/root/from.deb"; docker cp "$TO_DEB" "$NAME:/root/to.deb"
docker cp "$REPO/tests/sandbox/move_state.py" "$NAME:/root/move_state.py"
docker cp "$REPO/tests/sandbox/rfc2136_test.sh" "$NAME:/root/rfc2136_test.sh"
cat > "$OUT/secrets_dump.py" <<'PY'
import json, sys
sys.path.insert(0, "/opt/fabric/lib")
from fabriclib.secrets.load_secrets import load_secrets
print(json.dumps(load_secrets("/opt/fabric/config/fabric-secrets.yml").get("tsig_secrets") or {}))
PY
docker cp "$OUT/secrets_dump.py" "$NAME:/root/secrets_dump.py"
tsig_secret() { in_box 'python3 /root/secrets_dump.py' | python3 -c "import json,sys; print(json.load(sys.stdin)['$1'])"; }
t2136() { in_box "bash /root/rfc2136_test.sh $IP move.test acme '$1' web $BIND_PORT" 2>&1 | tail -1; }   # secret

echo "--- $FROM: installed and set up by its own setup"
in_box 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /root/from.deb' > "$OUT/apt-from.log" 2>&1
check "fabricctl $FROM installed" "in_box \"dpkg-query -W -f='\\\${Version}' fabricctl\" | grep -qx '$FROM'"
OLD_SECRET=$(openssl rand -base64 32)
cat > "$OUT/vars.yaml" <<EOF
domain: move.test
hostname: fabric-sbx
host_ip: $IP
lan_cidr: $SUBNET
lan_gateway: 10.78.0.1
friendly_name: Move test
ad_domain: ad.move.test
ad_password_policy: {minimum_length: 14, complexity: true, history: 24, minimum_age_days: 0, maximum_age_days: 0, lockout_threshold: 10, lockout_minutes: 15, lockout_window_minutes: 15}
install_keycloak: true
install_webui: true
install_fluentbit: true
dns_filter: bind
ntp_set_clock: false        # the sandbox shares the PC's kernel clock
tsig_keys:
- { name: acme, records: [web], secret: "$OLD_SECRET" }
- { name: ddns, record_types: [A, AAAA], records: [nas] }
dns:
  dynamic_zone_var:
    A: [{ name: nas, ip: 10.78.0.20 }]
    CNAME: [{ name: files, canonical: nas }]
  extra.test:
    zone_authority: true
    A: [{ name: printer, ip: 10.78.0.30 }]
EOF
docker cp "$OUT/vars.yaml" "$NAME:/root/vars.yaml"
( umask 077; printf '%s\n' "Mv7-$(openssl rand -hex 12)" > "$OUT/admin-pw" )
docker cp "$OUT/admin-pw" "$NAME:/root/admin-pw"
in_box 'fabricctl setup --file /root/vars.yaml --non-interactive --yes --approve all --admin-password-file /root/admin-pw' \
    > "$OUT/setup-from.log" 2>&1
check "$FROM: setup completes" "grep -q 'fabric is ready' '$OUT/setup-from.log'"
in_box 'python3 /root/move_state.py' > "$OUT/before.json" 2> "$OUT/before.err"
check "$FROM: the records are served and the key's rights hold (RFC2136 with its secret)" \
    "grep -q '10.78.0.30' '$OUT/before.json' && grep -q '10.78.0.20' '$OUT/before.json' \
     && [ \"\$(t2136 '$OLD_SECRET')\" = '4 passed, 0 failed' ]"
docker cp "$NAME:/opt/fabric/config/vars.yaml" "$OUT/vars-$FROM.yaml"
check "$FROM's settings file copied off the host (3.3.5.4 step 1)" "grep -q '^posix_id_start:' '$OUT/vars-$FROM.yaml'"
docker cp "$OUT/vars-$FROM.yaml" "$NAME:/root/vars-$FROM.yaml"

echo "--- the move (3.3.5.4): uninstall with an export, the candidate installed, setup --file the $FROM file"
in_box 'fabricctl uninstall --yes --export /root/fabric-export-before-080 --purge-package' > "$OUT/uninstall.log" 2>&1
check "$FROM uninstalled, its export kept" "! in_box 'test -e /opt/fabric' && in_box 'ls /root/fabric-export-before-080' >/dev/null"
in_box 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /root/to.deb' > "$OUT/apt-to.log" 2>&1
TO=$(in_box "dpkg-query -W -f='\${Version}' fabricctl")
check "the candidate installed ($TO)" "[ -n '$TO' ] && [ '$TO' != '$FROM' ]"
in_box "fabricctl setup --file /root/vars-$FROM.yaml --non-interactive --yes --approve all --admin-password-file /root/admin-pw" \
    > "$OUT/setup-refused.log" 2>&1
# covers: cli:setup -
check "unattended with the $FROM file as it is: refused before any step, naming every key to add" \
    "grep -q 'needs webui_admin_user in the vars file' '$OUT/setup-refused.log' \
     && grep -q 'webui_admin_first_name in the vars file' '$OUT/setup-refused.log' \
     && grep -q 'webui_admin_last_name in the vars file' '$OUT/setup-refused.log' \
     && ! grep -q '\[preflight\]' '$OUT/setup-refused.log' && ! in_box 'getent passwd fabric-dns'"
check "...having listed the keys it ignores (dc_name, the id settings, the log-on policies, the site OUs)" \
    "grep -q 'no longer takes, ignored' '$OUT/setup-refused.log' && grep -q '  dc_name: ' '$OUT/setup-refused.log' \
     && grep -q '  posix_id_start: ' '$OUT/setup-refused.log' && grep -q '  logon_policies: ' '$OUT/setup-refused.log' \
     && grep -q '  ad_site_ou: ' '$OUT/setup-refused.log'"
in_box "{ cat /root/vars-$FROM.yaml; printf 'webui_admin_user: moveadmin\nwebui_admin_first_name: Move\nwebui_admin_last_name: Admin\n'; } > /root/vars-moved.yaml"
in_box 'fabricctl setup --file /root/vars-moved.yaml --non-interactive --yes --approve all --admin-password-file /root/admin-pw' \
    > "$OUT/setup-to.log" 2>&1
# covers: cli:setup +
check "$TO: setup with the $FROM file and the first administrator's keys completes" "grep -q 'fabric is ready' '$OUT/setup-to.log'"
check "...the ignored keys listed and logged (SETUP_IMPORT)" \
    "grep -q 'no longer takes, ignored' '$OUT/setup-to.log' && in_box 'grep -q SETUP_IMPORT /opt/fabric/archive/audit.log'"
check "...the DC is fabric's own dc-0001, not $FROM's dc-<host>" "in_box 'grep -qx \"dc_name: dc-0001\" /opt/fabric/config/vars.yaml'"

in_box 'python3 /root/move_state.py' > "$OUT/after.json" 2> "$OUT/after.err"
for part in zones records "tsig keys" parts; do
    check "kept: the $part" "python3 -c \"import json,sys; a=json.load(open('$OUT/before.json'))['kept']; \
b=json.load(open('$OUT/after.json'))['kept']; sys.exit(a['$part'] != b['$part'])\""
done
check "made new: the root CA" "python3 -c \"import json,sys; a=json.load(open('$OUT/before.json'))['new']; \
b=json.load(open('$OUT/after.json'))['new']; sys.exit(a['root ca'] == b['root ca'] or b['root ca'] == 'missing')\""
check "made new: every TSIG key's secret" "python3 -c \"import json,sys; a=json.load(open('$OUT/before.json'))['new']; \
b=json.load(open('$OUT/after.json'))['new']; sys.exit(set(a['tsig secrets']) != set(b['tsig secrets']) \
or any(a['tsig secrets'][k] == b['tsig secrets'][k] for k in a['tsig secrets']))\""
NEW_SECRET=$(tsig_secret acme)
check "the key's rights hold with its new secret (RFC2136: its name taken, another refused)" \
    "[ \"\$(t2136 '$NEW_SECRET')\" = '4 passed, 0 failed' ]"
check "...and its old secret is refused" "[ \"\$(t2136 '$OLD_SECRET')\" != '4 passed, 0 failed' ]"
in_box 'fabricctl doctor' > "$OUT/doctor.log" 2>&1
check "doctor passes after the move" "! grep -q '✗' '$OUT/doctor.log' && grep -q '✓' '$OUT/doctor.log'"

echo; echo "$PASS passed, $FAIL failed   (logs: $OUT)"
exit $FAIL
