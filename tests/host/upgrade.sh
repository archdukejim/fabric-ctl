#!/bin/bash
# -----------------------------------------------------------------------
# Upgrade in place from the floor (0.8.0 until 1.0, 2.1.1.61) or the previous release (2.1.1.36), on a REAL host:
#   purge fabric -> install release FROM (its .deb from the GitHub release) -> setup -> seed state
#   (upgrade_state.py) and raise a sign-in layer -> snapshot -> upgrade to the candidate from fabric's apt
#   repository (TO_SUITE) -> fabricctl setup, as an operator would -> the same snapshot -> doctor, status.
#
#   TARGET=tempuser@192.168.4.57 HOST_IP=192.168.4.57 LAN_CIDR=192.168.4.0/22 GATEWAY=192.168.4.1 \
#   FROM=0.8.0 TO_SUITE=stable [DOMAIN=pitest.home.arpa] [KEY=~/.ssh/id] tests/host/upgrade.sh
#   (TO_DEB=<a .deb built here> instead of TO_SUITE: a branch not published to apt, e.g. a dev/ branch)
#
# It WIPES fabric on that host: use a disposable machine. Then run tests/host/run.sh with APT_SUITE=TO_SUITE
# for the whole host suite on the upgraded install.
#
# A FROM older than the floor is refused before the host is touched: there is no upgrade into 0.8.0 (2.1.1.60); a
# 0.7.x install moves by its settings file (3.3.5), which tests/sandbox/move.sh tests. FROM_CHECK_ONLY=1 stops after
# that check (tests/host/upgrade_from_test.sh).
# -----------------------------------------------------------------------
set -uo pipefail
FLOOR=0.8.0                     # 2.1.1.61: 0.8.0 until 1.0, then 1.0.0 (2.1.1.55)
: "${TARGET:?user@host}" "${HOST_IP:?}" "${LAN_CIDR:?}" "${GATEWAY:?}" "${FROM:?the floor or the previous release, e.g. 0.8.0}" \
  "${TO_SUITE:=${TO_DEB:+local}}" "${TO_SUITE:?stable or testing (or TO_DEB=<.deb>)}"
if ! [[ "$FROM" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "FROM=$FROM is not a release version (e.g. $FLOOR)" >&2; exit 2
fi
if [ "$(printf '%s\n%s\n' "$FLOOR" "$FROM" | sort -V | head -1)" != "$FLOOR" ]; then
    echo "FROM=$FROM is older than the upgrade floor $FLOOR (2.1.1.61): nothing upgrades into 0.8.0 (2.1.1.60); a" \
         "0.7.x install moves by its settings file (manual 3.3.5), tested by tests/sandbox/move.sh" >&2
    exit 2
fi
if [ -n "${FROM_CHECK_ONLY:-}" ]; then echo "FROM=$FROM: at or above the floor $FLOOR"; exit 0; fi
DOMAIN="${DOMAIN:-pitest.home.arpa}"
KEY="${KEY:-$HOME/.ssh/fabric-test_ed25519}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FABRIC_TEST_OUT:-/tmp/fabric-tests}/upgrade"
APT_URL="${APT_URL:-https://archdukejim.github.io/fabric-ctl}"
RELEASES="${RELEASES:-https://github.com/archdukejim/fabric-ctl/releases/download}"
SSH=(ssh -o BatchMode=yes -o ServerAliveInterval=30 -i "$KEY" "$TARGET")
PASS=0; FAIL=0
check() { if (set +o pipefail; eval "$2"); then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
R() { "${SSH[@]}" "sudo bash -lc $(printf '%q' "$*")"; }          # run as root on the host
put() { scp -q -o BatchMode=yes -i "$KEY" "$1" "$TARGET:/tmp/$(basename "$1")"; }
rm -rf "$OUT"; mkdir -p "$OUT"
HOSTNAME_=$("${SSH[@]}" 'hostname -s')

echo "--- wipe: apt purge (its export goes to /var/backups/fabric)"
R 'DEBIAN_FRONTEND=noninteractive apt-get purge -y -q fabricctl; rm -f /etc/apt/sources.list.d/fabric.list' \
    > "$OUT/purge.log" 2>&1
check "the host starts without fabric" "! R 'dpkg -s fabricctl' >/dev/null 2>&1 && ! R 'test -e /opt/fabric'"

echo "--- install the previous release, $FROM, from its GitHub release"
R "cd /tmp && rm -f fabricctl_${FROM}_all.deb && wget -q $RELEASES/v$FROM/fabricctl_${FROM}_all.deb && \
   apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ./fabricctl_${FROM}_all.deb" \
    > "$OUT/install-from.log" 2>&1
check "fabricctl $FROM installed" "R \"dpkg-query -W -f='\\\${Version}' fabricctl\" | grep -qx '$FROM'"
cat > "$OUT/vars.yaml" <<EOF
domain: $DOMAIN
hostname: $HOSTNAME_
host_ip: $HOST_IP
lan_cidr: $LAN_CIDR
lan_gateway: $GATEWAY
friendly_name: Fabric upgrade test
ad_domain: ad.$DOMAIN
ad_password_policy: {minimum_length: 14, complexity: true, history: 24, minimum_age_days: 0, maximum_age_days: 0, lockout_threshold: 10, lockout_minutes: 15, lockout_window_minutes: 15}
install_keycloak: true
install_webui: true
webui_admin_user: upgadmin
webui_admin_first_name: Upgrade
webui_admin_last_name: Admin
EOF
put "$OUT/vars.yaml"
start=$(date +%s)
# the first Directory Administrator's password (2.1.6.69): made on the host, root-only, never on a command line
R 'umask 077; printf "%sAa1-\n" "$(head -c 18 /dev/urandom | base64 | tr -d "/+=")" > /root/upgrade-admin-pw'
R "fabricctl setup --file /tmp/vars.yaml --non-interactive --yes --approve all --admin-password-file /root/upgrade-admin-pw" \
    > "$OUT/setup-from.log" 2>&1
echo "    setup ($FROM) took $(( ($(date +%s) - start) / 60 )) min"
check "$FROM: setup completes" "grep -q 'fabric is ready' '$OUT/setup-from.log'"

echo "--- seed what an upgrade must keep"
put "$REPO/tests/host/upgrade_state.py"
R 'python3 /tmp/upgrade_state.py seed && fabricctl --apply' > "$OUT/seed.log" 2>&1
# the device certificate for the snapshot: its .p12 password goes to a root-only file, never to these logs
R "fabricctl client-cert carol | sed -n 's/^.p12 password (shown once): //p' > /root/upgrade-test-carol.pw &&    openssl pkcs12 -in \$(getent passwd \$(logname 2>/dev/null || echo \$SUDO_USER) | cut -d: -f6)/fabric-admin/carol.p12    -nokeys -clcerts -passin file:/root/upgrade-test-carol.pw -out /root/upgrade-test-carol.pem &&    rm -f /root/upgrade-test-carol.pw && echo carol certificate" > "$OUT/client-cert.log" 2>&1
R 'fabricctl security raise admin-2fa totp' > "$OUT/raise.log" 2>&1
R 'python3 /tmp/upgrade_state.py snapshot' > "$OUT/before.json" 2>"$OUT/before.err"
check "seeded: the person, the record, the certificate, the DNS filter rule, the raised layer" \
    "grep -q '192.0.2.55' '$OUT/before.json' && grep -q '\"dns filter rule\": true' '$OUT/before.json' && \
     grep -q 'admin-2fa totp' '$OUT/before.json' && grep -q 'objectGUID' '$OUT/before.json' && \
     grep -q 'upgrade-test-carol.pem: OK' '$OUT/before.json' && grep -q 'objectGUID' '$OUT/before.json'"

echo "--- upgrade to the candidate from ${TO_DEB:-apt $TO_SUITE}"
if [ -n "${TO_DEB:-}" ]; then
    put "$TO_DEB"
    R "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/$(basename "$TO_DEB")" > "$OUT/upgrade.log" 2>&1
else
R "wget -qO- $APT_URL/public.key | gpg --dearmor --yes -o /usr/share/keyrings/fabric-archive-keyring.gpg && \
   echo 'deb [signed-by=/usr/share/keyrings/fabric-archive-keyring.gpg] $APT_URL $TO_SUITE main' \
   > /etc/apt/sources.list.d/fabric.list && apt-get update -qq && \
   DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fabricctl" > "$OUT/upgrade.log" 2>&1
fi
TO=$(R "dpkg-query -W -f='\${Version}' fabricctl")
check "the package moved from $FROM to $TO" "[ -n '$TO' ] && [ '$TO' != '$FROM' ]"
start=$(date +%s)
# as an operator after `apt upgrade`: asked again only what is new (APPROVE: the groups an unattended run answers)
R "fabricctl setup --non-interactive --yes ${APPROVE:+--approve $APPROVE} ${DECLINE:+--decline $DECLINE}" > "$OUT/setup-to.log" 2>&1
echo "    setup ($TO) took $(( ($(date +%s) - start) / 60 )) min"
check "$TO: setup completes over the old install" "grep -q 'fabric is ready' '$OUT/setup-to.log'"

R 'python3 /tmp/upgrade_state.py snapshot' > "$OUT/after.json" 2>"$OUT/after.err"
check "kept: secrets (each one there before, unchanged; new ones may be added, Keycloak's database password rotates)"     "python3 -c \"import json,sys; a=json.load(open('$OUT/before.json'))['secrets']; b=json.load(open('$OUT/after.json'))['secrets']; sys.exit(any(b.get(k) != v for k, v in a.items()))\""
for key in "root_ca" "person carol" "issued" "dns record" "dns filter rule" "security"; do
    check "kept: $key" "python3 -c \"import json,sys; a=json.load(open('$OUT/before.json')); \
b=json.load(open('$OUT/after.json')); sys.exit(a.get('$key') != b.get('$key'))\""
done
ADMIN_KEY=$(python3 -c "import json; print([k for k in json.load(open('$OUT/before.json')) if k.startswith('person ') and k != 'person carol'][0])")
check "kept: the admin ($ADMIN_KEY), password unchanged" "python3 -c \"import json,sys; \
a=json.load(open('$OUT/before.json')); b=json.load(open('$OUT/after.json')); sys.exit(a['$ADMIN_KEY'] != b['$ADMIN_KEY'])\""
R 'fabricctl doctor' > "$OUT/doctor.log" 2>&1
check "doctor passes after the upgrade" "! grep -q '✗' '$OUT/doctor.log' && grep -q '✓' '$OUT/doctor.log'"
R 'fabricctl status' > "$OUT/status.log" 2>&1
check "every container healthy after the upgrade" "[ \"\$(grep -c ' healthy' '$OUT/status.log')\" -ge 7 ]"
check "no 'package is newer than the running install' warning left" "! grep -qi 'newer than the running' '$OUT/status.log'"

echo; echo "$PASS passed, $FAIL failed   (logs: $OUT; next: APT_SUITE=$TO_SUITE tests/host/run.sh)"
exit $FAIL
