#!/bin/bash
# -----------------------------------------------------------------------
# End-to-end test on a REAL host (e.g. a Raspberry Pi) over SSH, from the
# package, as users install it:
#   apt install ./fabricctl_<v>_all.deb -> fabricctl setup --file vars.yaml
#   -> doctor, fabric.target, info.<domain>/certs/ (HTTP + HTTPS), RFC2136 with an
#   embedded TSIG key, restricted sign-in (real Keycloak), re-run, stop/start.
#
#   TARGET=tempuser@192.168.4.57 HOST_IP=192.168.4.57 LAN_CIDR=192.168.4.0/22 \
#   GATEWAY=192.168.4.1 [DOMAIN=pitest.home.arpa] [KEY=~/.ssh/id] [EXTRA_VARS=$'site_name: lan\nldap_base_dn: dc=lan'] \
#   [APT_SUITE=stable|testing] tests/host/run.sh
#   (APT_SUITE: install from fabric's signed apt repository, as users do, instead of a .deb built here)
#
# It INSTALLS fabric on that host (Docker, firewall, services): use a
# disposable machine. The install is left in place; CLEANUP=1 uninstalls it.
# The SSH user needs key login and passwordless sudo.
# -----------------------------------------------------------------------
set -uo pipefail
: "${TARGET:?user@host}" "${HOST_IP:?}" "${LAN_CIDR:?}" "${GATEWAY:?}"
DOMAIN="${DOMAIN:-pitest.home.arpa}"
KEY="${KEY:-$HOME/.ssh/fabric-test_ed25519}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FABRIC_TEST_OUT:-/tmp/fabric-tests}/host"
SSH=(ssh -o BatchMode=yes -o ServerAliveInterval=30 -i "$KEY" "$TARGET")
PASS=0; FAIL=0
check() { if (set +o pipefail; eval "$2"); then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
R() { "${SSH[@]}" "sudo bash -lc $(printf '%q' "$*")"; }          # run as root on the host
put() { scp -q -o BatchMode=yes -i "$KEY" "$1" "$TARGET:/tmp/$(basename "$1")"; }
rm -rf "$OUT"; mkdir -p "$OUT"

LOGIN=$("${SSH[@]}" whoami); HOSTNAME_=$("${SSH[@]}" 'hostname -s')
echo "--- target: $TARGET ($("${SSH[@]}" 'uname -m; . /etc/os-release; echo $PRETTY_NAME' | tr '\n' ' '))"

if [ -n "${APT_SUITE:-}" ]; then
    # as users install it (manual 3.3.1): fabric's signed apt repository on GitHub Pages, suite stable or testing
    APT_URL="${APT_URL:-https://archdukejim.github.io/open-fabric}"
    R "wget -qO- $APT_URL/public.key | gpg --dearmor --yes -o /usr/share/keyrings/fabric-archive-keyring.gpg &&        echo 'deb [signed-by=/usr/share/keyrings/fabric-archive-keyring.gpg] $APT_URL $APT_SUITE main'        > /etc/apt/sources.list.d/fabric.list && apt-get update &&        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fabricctl" > "$OUT/apt.log" 2>&1
    check "fabric's apt repository ($APT_SUITE) is trusted by its key and installs fabricctl"         "R 'dpkg -s fabricctl' | grep -q '^Status: install ok installed' && ! grep -qiE 'NO_PUBKEY|not signed|GPG error' '$OUT/apt.log'"
else
    DEB=$(OUT="$OUT/dist" bash "$REPO/packaging/deb/build-deb.sh") || { echo "FAIL package build"; exit 1; }
    put "$DEB"
    R "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/$(basename "$DEB")" > "$OUT/apt.log" 2>&1
    check "package installs with apt on the host" "R 'dpkg -s fabricctl' | grep -q '^Status: install ok installed'"
fi

TSIG_SECRET=$(openssl rand -base64 32)
cat > "$OUT/vars.yaml" <<EOF
domain: $DOMAIN
hostname: $HOSTNAME_
host_ip: $HOST_IP
lan_cidr: $LAN_CIDR
lan_gateway: $GATEWAY
friendly_name: Fabric host test
ad_domain: ad.$DOMAIN
ad_password_policy: {minimum_length: 14, complexity: true, history: 24, minimum_age_days: 0, maximum_age_days: 0, lockout_threshold: 10, lockout_minutes: 15, lockout_window_minutes: 15}
install_keycloak: true
install_webui: true
tsig_keys:
- { name: npm, records: [npm], secret: "$TSIG_SECRET", acls: [npm-updaters] }
EOF
# EXTRA_VARS: more settings for a fresh install, one YAML line each (e.g. "site_name: lan" for a federation root)
[ -n "${EXTRA_VARS:-}" ] && printf '%s\n' "$EXTRA_VARS" >> "$OUT/vars.yaml"
put "$OUT/vars.yaml"

echo "--- setup (this host builds its images; takes a while on a Pi)"
start=$(date +%s)
# the first admin's password for a fresh install, in a 0600 file (2.1.6.33: never on a command line); a re-run on an
# install that has its admin ignores it
ADMIN_PW="Fx9-$(openssl rand -hex 12)"
( umask 077; printf '%s\n' "$ADMIN_PW" > "$OUT/admin-pw" )
scp -q -p -o BatchMode=yes -i "$KEY" "$OUT/admin-pw" "$TARGET:/tmp/admin-pw"
R "fabricctl setup --file /tmp/vars.yaml --non-interactive --yes --approve all --admin-password-file /tmp/admin-pw" \
    > "$OUT/setup.log" 2>&1
R "rm -f /tmp/admin-pw"
echo "    setup took $(( ($(date +%s) - start) / 60 )) min"
check "setup completes" "grep -q 'fabric is ready' '$OUT/setup.log'"
R 'fabricctl doctor' > "$OUT/doctor.log" 2>&1
check "doctor: all checks pass" "! grep -q '✗' '$OUT/doctor.log' && grep -q '✓' '$OUT/doctor.log'"
check "fabric.target enabled and active" "R 'systemctl is-enabled fabric.target && systemctl is-active fabric.target' >/dev/null"
R 'fabricctl status' > "$OUT/status.log" 2>&1
check "every container healthy" "[ \"\$(grep -c ' healthy' '$OUT/status.log')\" -ge 7 ]"

NGINX_IP=$(R "python3 -c 'import yaml;print(yaml.safe_load(open(\"/opt/fabric/config/vars.yaml\"))[\"ip_nginx\"])'")
for f in certs_page_test.sh rfc2136_test.sh login_test.py; do put "$REPO/tests/sandbox/$f"; done
R "bash /tmp/certs_page_test.sh info.$DOMAIN ca.$DOMAIN $NGINX_IP $HOST_IP" > "$OUT/certs-page.log" 2>&1
check "certs page at info.<domain>/certs/: formats, CA identity, MIME, plain HTTP by name and IP, CRLs, ca.<domain> = Step-CA, certs.<domain> gone" \
    "! grep -q '^FAIL' '$OUT/certs-page.log' && [ \"\$(grep -c '^PASS' '$OUT/certs-page.log')\" -ge 25 ]"
check "LAN clients reach the certificate page over plain HTTP: http://$HOST_IP/certs/" \
    "curl -s --max-time 10 http://$HOST_IP/certs/root-ca.pem | grep -q 'BEGIN CERTIFICATE'"

BIND_PORT=$(R "awk '/^bind_dns_port:/ {print \$2}' /opt/fabric/config/vars.yaml")    # 5053 behind the DNS filter
R "bash /tmp/rfc2136_test.sh $HOST_IP $DOMAIN npm '$TSIG_SECRET' npm $BIND_PORT" > "$OUT/rfc2136.log" 2>&1
check "RFC2136 to BIND's port ($BIND_PORT) with the embedded TSIG key (npm): allowed name only, wrong keys refused" "grep -q '4 passed, 0 failed' '$OUT/rfc2136.log'"
# the DNS filter is on by default (2.1.12.3): the BIND resolver on 53 in front of BIND on 5053, Cloudflare over DoT,
# AdGuard's DNS filter list
check "DNS filter on by default: the resolver on 53 answers fabric's names, BIND behind it on 5053" \
    "R 'dig +short @$HOST_IP ns.$DOMAIN' | grep -qx $HOST_IP && R 'dig +short -p 5053 @$HOST_IP ns.$DOMAIN' | grep -qx $HOST_IP"
# AdGuard Home blocks (2.1.12.6): its answer, not the old engine's RPZ log
check "DNS filter: internet names resolve; an ad domain blocked by the AdGuard DNS filter list" \
    "R 'dig @$HOST_IP example.com' | grep -q 'status: NOERROR' && \
     R 'dig @$HOST_IP ads.doubleclick.net' | grep -q 'status: NXDOMAIN'"
# DNSSEC is validated somewhere on the way (1.12.3.2): a name whose signatures are broken is refused (2.3.1.19.3)
check "DNS filter: DNSSEC validated: a name with broken signatures (dnssec-failed.org) is refused" \
    "R 'dig @$HOST_IP +time=10 dnssec-failed.org' | grep -q 'status: SERVFAIL'"

echo "--- restricted sign-in (real Keycloak)"
cat > "$OUT/bob.py" <<'PY'
import sys, yaml
sys.path.insert(0, "/opt/fabric/lib")
from fabriclib.common.errors import ValidationError
from fabriclib.directory.create_person import create_person
v = yaml.safe_load(open("/opt/fabric/config/vars.yaml"))
try:                                      # a person of the site, not an admin; re-runs find bob there already
    create_person(v, "test", "bob", "Bob", "Test", "bob@example.invalid", source="test")
    print("bob created")
except ValidationError as e:
    print(f"bob: {e}")
PY
put "$OUT/bob.py"
R "python3 /tmp/bob.py" > "$OUT/bob.log" 2>&1
BOB_P12_PW=$(R 'fabricctl client-cert bob' 2>&1 | sed -n 's/^.p12 password (shown once): //p')
KIT=$(R "getent passwd $LOGIN | cut -d: -f6")/fabric-admin
# The admin and bob at their first sign-in (also on a re-run on the same machine): a new one-time password each,
# from fabric's own reset; the admin's into the login kit, as setup leaves it
put "$REPO/tests/host/reset_user.py"
ADMIN=$(R "awk '/^webui_admin_user:/{print \$2}' /opt/fabric/config/vars.yaml")
R "python3 /tmp/reset_user.py $ADMIN $KIT/initial-password.txt" > "$OUT/reset.log" 2>&1
R "python3 /tmp/reset_user.py bob /root/fabric-test-bob-password" >> "$OUT/reset.log" 2>&1
BOB_PW=$(R 'cat /root/fabric-test-bob-password; rm -f /root/fabric-test-bob-password')
# 0.6.1's default (2.1.6.23): no client certificate, a password only; the console's Security page there to raise them
R "SIGNIN_MODE=plain FABRIC_KIT=$KIT python3 /tmp/login_test.py /opt/fabric/config/vars.yaml bob '$BOB_PW' ''" \
    > "$OUT/login-plain.log" 2>&1
check "sign-in by default: no certificate asked, the admin in with a password only, a non-admin refused (2.1.6.23)" \
    "! grep -q '^FAIL' '$OUT/login-plain.log' && [ \"\$(grep -c '^PASS' '$OUT/login-plain.log')\" -ge 4 ]"
check "status shows the password-only sign-in as a relaxation (Rule 10, 2.1.6.23)" \
    "R 'fabricctl status' | grep -q 'signin_admin_second_factor: none'"

echo "--- raising sign-in security (fabricctl security raise: the apply and Keycloak, as the Security page does)"
R 'fabricctl security raise admin-2fa totp && fabricctl security raise client-cert on' > "$OUT/raise.log" 2>&1
# covers: cli:security.raise cli:security +
check "raise: TOTP for the admin tools and the client certificate, applied" \
    "[ \"\$(grep -c '^done: ' '$OUT/raise.log')\" -eq 2 ] && R 'fabricctl security' | grep -qE '^admin-2fa +totp' && \
     R 'fabricctl security' | grep -qE '^client-cert +on'"

echo "--- re-run and restart"
R 'fabricctl setup --non-interactive --yes' > "$OUT/setup2.log" 2>&1
check "setup re-run converges (no certificate re-issued); the kit gets the admin's .p12 now the console asks for one" \
    "grep -q 'fabric is ready' '$OUT/setup2.log' && ! grep -q ': issued' '$OUT/setup2.log' && \
     R 'test -s $KIT/$ADMIN.p12 && test -s $KIT/p12-password.txt'"
R "python3 /tmp/reset_user.py $ADMIN $KIT/initial-password.txt" >> "$OUT/reset.log" 2>&1
R "python3 /tmp/reset_user.py bob /root/fabric-test-bob-password" >> "$OUT/reset.log" 2>&1
BOB_PW=$(R 'cat /root/fabric-test-bob-password; rm -f /root/fabric-test-bob-password')
R "FABRIC_KIT=$KIT NEW_PERSON=dave$(date +%s) python3 /tmp/login_test.py /opt/fabric/config/vars.yaml bob '$BOB_PW' '$BOB_P12_PW'" > "$OUT/login.log" 2>&1
check "sign-in raised: admin in with TOTP; HTTP, missing/foreign certs, non-admin and borrowed certs refused" \
    "! grep -q '^FAIL' '$OUT/login.log' && [ \"\$(grep -c '^PASS' '$OUT/login.log')\" -ge 11 ]"
check "login kit in the admin's home ($KIT), secrets 0600" \
    "[ \"\$(R 'stat -c %a $KIT/p12-password.txt $KIT/initial-password.txt' | sort -u)\" = 600 ]"

echo "--- lowering (only on the host, the layer's name typed back at a terminal)"
R "printf 'nope\n' | script -qec 'fabricctl security lower client-cert' /dev/null; fabricctl security" > "$OUT/lower1.log" 2>&1
check "lower: a wrong name typed back changes nothing" "grep -qE '^client-cert +on' '$OUT/lower1.log'"
R "fabricctl security lower client-cert --yes" > "$OUT/lower2.log" 2>&1
# covers: cli:security.lower -
check "lower: --yes is refused" "grep -q 'never by --yes' '$OUT/lower2.log'"
R "printf 'client-cert\n' | script -qec 'fabricctl security lower client-cert' /dev/null" > "$OUT/lower3.log" 2>&1
R 'fabricctl doctor' > "$OUT/doctor-lowered.log" 2>&1
# covers: cli:security.lower ask:security.lower.confirm +
check "lower: the name typed back lowers it; doctor warns about it (and still passes)" \
    "grep -q '^done: ' '$OUT/lower3.log' && grep -q 'client-cert lowered: on -> off' '$OUT/doctor-lowered.log' && \
     ! grep -q '✗' '$OUT/doctor-lowered.log' && R \"grep -q 'SECURITY_LOWER' /opt/fabric/archive/audit.log\""
R 'fabricctl stop' > /dev/null 2>&1
check "fabricctl stop: DNS goes quiet" "! R 'dig +time=2 +tries=1 +short @$HOST_IP ns.$DOMAIN' | grep -qx $HOST_IP"
R 'fabricctl start' > /dev/null 2>&1
R 'fabricctl doctor' > "$OUT/doctor2.log" 2>&1
check "fabricctl start: back, doctor passes" "! grep -q '✗' '$OUT/doctor2.log' && grep -q '✓' '$OUT/doctor2.log'"

cat > "$OUT/argv_check.py" <<'PY'
import glob, sys
sys.path.insert(0, "/opt/fabric/lib")
from fabriclib.secrets.load_secrets import load_secrets   # the file, or OpenBao once imported
secrets = load_secrets("/opt/fabric/config/fabric-secrets.yml")
leaks = set()
for path in glob.glob("/proc/[0-9]*/cmdline"):
    try:
        argv = open(path, "rb").read().decode(errors="replace")
    except OSError:
        continue
    leaks.update(k for k, v in secrets.items() if isinstance(v, str) and len(v) >= 12 and v in argv)
print("LEAKS:", sorted(leaks) if leaks else "none")
PY
put "$OUT/argv_check.py"
check "no secret in any process's argv" "R 'python3 /tmp/argv_check.py' | grep -q 'LEAKS: none'"

if [ "${CLEANUP:-0}" = 1 ]; then
    # apt purge: apt cannot ask, so fabric's data is exported to /var/backups/fabric/ first
    R 'DEBIAN_FRONTEND=noninteractive apt-get purge -y -q fabricctl' > "$OUT/uninstall.log" 2>&1
    check "apt purge: data exported to /var/backups/fabric, fabric removed"         "R 'ls -d /var/backups/fabric/fabric-export-*/stepca/data' >/dev/null 2>&1 && ! R 'test -e /opt/fabric' && ! R 'dpkg -s fabricctl' >/dev/null 2>&1"
fi
echo; echo "$PASS passed, $FAIL failed   (logs: $OUT)"
exit $FAIL
