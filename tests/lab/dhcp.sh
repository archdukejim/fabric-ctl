#!/bin/bash
# -----------------------------------------------------------------------
# The DHCP lab suite (manual 1.10.3.8, the gate for 0.8): fabric serving DHCP on an isolated network beyond the
# host's LAN, with real Ubuntu clients. The server's second interface sits on a switch of its own (no router); the
# clients' second interfaces too (manual 2.3.1.9.6). Over SSH, by name:
#
#   SERVER=g23-vm-ub24-1 CLIENTS="g23-vm-ub22-1 g23-vm-ub20-1" tests/lab/dhcp.sh
#   [REUSE=1: keep the server's install from the last run; DHCP is turned off first]
#   [LAB_IF=eth1 LAB_NET=10.20.0.0/24 LAB_ADDR=10.20.0.10 POOL="10.20.0.100 - 10.20.0.199" DOMAIN=lab.home.arpa]
#
# It WIPES fabric on SERVER and installs this checkout's package there; clients get a DHCP connection on their lab
# interface. The lab address must already be on the server's LAB_IF. Never on a network with another DHCP server.
# -----------------------------------------------------------------------
set -uo pipefail
: "${SERVER:?ssh name of the fabric host}" "${CLIENTS:?ssh names of the lab clients}"
LAB_IF="${LAB_IF:-eth1}"; LAB_NET="${LAB_NET:-10.20.0.0/24}"; LAB_ADDR="${LAB_ADDR:-10.20.0.10}"
POOL="${POOL:-10.20.0.100 - 10.20.0.199}"; DOMAIN="${DOMAIN:-lab.home.arpa}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FABRIC_TEST_OUT:-/tmp/fabric-tests}/lab-dhcp"
PASS=0; FAIL=0
check() { if (set +o pipefail; eval "$2"); then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
# Purpose: run a command on a lab machine: its output without OpenSSH's notices, and the command's own exit status (a
#          filter's would hide it: a quiet command would look failed, and a negated one passed).
on() {
    local out rc
    out=$(ssh -o ConnectTimeout=20 "$1" "$2" 2>&1); rc=$?
    printf '%s\n' "$out" | grep -v "post-quantum\|store now\|upgraded. See\|^$" || true
    return $rc
}
# Purpose: whether a client fetches https://info.<domain>/ by name, through its own resolver (fabric's), with fabric's
#          CA verified: Python's TLS, as not every desktop has curl.
# Inputs:  $1 — the client's ssh name (fabric's root CA already in /tmp/fabric-root.crt there).
https_ok() {
    on "$1" "python3 -c \"import ssl, urllib.request as u; print(u.urlopen('https://info.$DOMAIN/', timeout=15,
        context=ssl.create_default_context(cafile='/tmp/fabric-root.crt')).status)\"" | grep -qx 200
}
R() { on "$SERVER" "sudo bash -lc $(printf '%q' "$1")"; }
rm -rf "$OUT"; mkdir -p "$OUT"

# Purpose: renew a client's lease on its lab interface (NetworkManager), creating the connection the first time.
# Inputs:  $1 — the client's ssh name.
# Returns: its lab address after the renewal on stdout ("" when it has none).
renew() {
    on "$1" "c=\$(nmcli -t -f NAME,DEVICE con show | awk -F: '\$2==\"$LAB_IF\"{print \$1}' | head -1);
             [ -n \"\$c\" ] || { sudo nmcli con add type ethernet ifname $LAB_IF con-name fabric-lab ipv4.method auto \
                                   ipv6.method disabled >/dev/null; c=fabric-lab; }
             sudo nmcli con up \"\$c\" >/dev/null 2>&1; sleep 6
             ip -4 -o addr show $LAB_IF | awk '{print \$4}' | cut -d/ -f1 | head -1"
}

if [ -n "${REUSE:-}" ]; then     # REUSE=1: the install from the last run, DHCP turned off (quicker reruns of the checks)
    R "fabricctl dhcp off" >/dev/null 2>&1
    HOST_IP=$(R "ip -4 -o route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p'")
else
echo "--- the server: wiped, this checkout's package, setup with DHCP off"
DEB=$(OUT="$OUT/dist" bash "$REPO/packaging/deb/build-deb.sh") || { echo "FAIL package build"; exit 1; }
scp -q "$DEB" "$SERVER:/tmp/"
R "fabricctl uninstall --yes --no-export >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq fabricctl \
   >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/$(basename "$DEB") >/dev/null 2>&1"
HOST_IP=$(R "ip -4 -o route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p'")
GW=$(R "ip -4 route show default | awk '{print \$3; exit}'")
CIDR=$(R "ip -4 -o addr show | awk -v ip=$HOST_IP '\$4 ~ \"^\"ip\"/\" {print \$4}'" | python3 -c \
       "import ipaddress,sys; print(ipaddress.ip_interface(sys.stdin.read().strip()).network)")
check "the server has the lab address $LAB_ADDR on $LAB_IF" "R 'ip -4 -o addr show $LAB_IF' | grep -q ' $LAB_ADDR/'"
cat > "$OUT/vars.yaml" <<EOF
domain: $DOMAIN
hostname: $(on "$SERVER" 'hostname -s')
host_ip: $HOST_IP
lan_cidr: $CIDR
lan_gateway: $GW
friendly_name: Fabric DHCP lab
ad_domain: ad.$DOMAIN
install_keycloak: true
install_webui: true
# the first Directory Administrator (2.1.6.69): required by --non-interactive
webui_admin_user: lab.admin
webui_admin_first_name: Lab
webui_admin_last_name: Admin
EOF
( umask 077; printf 'Fx9-%s\n' "$(openssl rand -hex 12)" > "$OUT/admin-pw" )
scp -q "$OUT/vars.yaml" "$SERVER:/tmp/lab-vars.yaml"; scp -q -p "$OUT/admin-pw" "$SERVER:/tmp/admin-pw"
R "fabricctl setup --file /tmp/lab-vars.yaml --non-interactive --yes --approve all --admin-password-file /tmp/admin-pw; \
   rm -f /tmp/admin-pw" > "$OUT/setup.log" 2>&1
check "setup completes with DHCP off" "grep -q 'fabric is ready' '$OUT/setup.log' && ! R 'systemctl is-active kea' | grep -qx active"
fi

echo "--- DHCP on, the first subnet on $LAB_IF (fabricctl dhcp on)"
R "fabricctl dhcp on --interface $LAB_IF --subnet $LAB_NET --pool '$POOL'" > "$OUT/on.log" 2>&1
# covers: cli:dhcp.on +
check "dhcp on: applied and the host firewall brought in line" "grep -q 'applied' '$OUT/on.log' && grep -q 'host firewall: in line' '$OUT/on.log'"
check "Kea runs, listening on $LAB_ADDR:67" "R 'ss -ulpn' | grep -q '$LAB_ADDR:67 '"
check "ufw lets DHCP in on $LAB_IF (67/udp)" "R 'ufw status' | grep -E '67/udp' | grep -q '$LAB_IF'"
R "fabricctl dhcp on" > "$OUT/on-again.log" 2>&1
# covers: cli:dhcp.on -
check "dhcp on when on: refused, saying so" "grep -q 'already on' '$OUT/on-again.log'"

echo "--- the clients"
CA=$(R "cat /opt/stepca/data/certs/root_ca.crt")
for c in $CLIENTS; do
    printf '%s\n' "$CA" | on "$c" "cat > /tmp/fabric-root.crt"
    ip=$(renew "$c")
    check "$c: a lease from the pool ($ip)" "python3 -c \"import ipaddress as i,sys; lo,hi=[i.ip_address(x.strip()) for x in '$POOL'.split('-')]; sys.exit(not lo <= i.ip_address('$ip') <= hi)\" 2>/dev/null"
    check "$c: told to use fabric's address on the lab ($LAB_ADDR) for DNS" \
        "on $c 'resolvectl status $LAB_IF' | grep -q 'DNS Servers: $LAB_ADDR'"
    check "$c: a route to host_ip ($HOST_IP) through $LAB_ADDR (option 121)" \
        "on $c 'ip route get $HOST_IP' | grep -q 'via $LAB_ADDR dev $LAB_IF'"
    name="$(on "$c" 'hostname -s').dhcp.$DOMAIN"
    check "$c: its name $name resolves to its lease, through fabric" \
        "[ \"\$(on $c 'dig +short $name @$LAB_ADDR')\" = '$ip' ]"
    check "$c: its PTR, through fabric (2.1.10.7)" \
        "for i in \$(seq 10); do [ \"\$(on $c 'dig +short -x $ip @$LAB_ADDR')\" = '$name.' ] && exit 0; sleep 3; done; exit 1"
    check "$c: https://info.$DOMAIN by name, fabric's CA verified" \
        "https_ok $c"
done
first=${CLIENTS%% *}

echo "--- a reservation"
MAC=$(on "$first" "cat /sys/class/net/$LAB_IF/address")
R "fabricctl dhcp reserve $MAC 10.20.0.50 labresv" > "$OUT/reserve.log" 2>&1
on "$first" "sudo nmcli dev disconnect $LAB_IF >/dev/null 2>&1; true"
sleep 2
check "$first: the reserved address 10.20.0.50 after a new lease" "renew $first >/dev/null; for i in \$(seq 15); do [ \"\$(on $first 'ip -4 -o addr show $LAB_IF | grep -o 10.20.0.50')\" = 10.20.0.50 ] && exit 0; sleep 2; done; exit 1"
R "fabricctl dhcp unreserve $MAC" > /dev/null 2>&1

echo "--- a guest subnet: DNS only (2.1.10.4)"
R "python3 - <<'PY'
import yaml
p = '/opt/fabric/config/vars.yaml'
v = yaml.safe_load(open(p))
v['dhcp']['subnets'][0]['access'] = 'guest'
yaml.safe_dump(v, open(p, 'w'), default_flow_style=False)
PY
fabricctl --apply >/dev/null 2>&1; python3 /opt/fabric/lib/fabriclib/cli.py setup --step firewall --non-interactive --approve ports >/dev/null 2>&1"
check "guest: DNS still answers" "on $first 'dig +short info.$DOMAIN @$LAB_ADDR' | grep -q ."
check "guest: fabric's pages refused (443)" "! on $first 'curl -s -m 8 -o /dev/null -w %{http_code} -k https://$LAB_ADDR/' | grep -q '^[1-5]'"
R "python3 - <<'PY'
import yaml
p = '/opt/fabric/config/vars.yaml'
v = yaml.safe_load(open(p))
v['dhcp']['subnets'][0].pop('access', None)
yaml.safe_dump(v, open(p, 'w'), default_flow_style=False)
PY
fabricctl --apply >/dev/null 2>&1; python3 /opt/fabric/lib/fabriclib/cli.py setup --step firewall --non-interactive --approve ports >/dev/null 2>&1"
check "full again: the pages answer" "on $first 'curl -s -m 8 -o /dev/null -w %{http_code} -k https://$LAB_ADDR/' | grep -q '^[1-5]'"

echo "--- off, then on again"
R "fabricctl dhcp off" > "$OUT/off.log" 2>&1
# covers: cli:dhcp.off +
check "dhcp off: applied, Kea stopped and its unit removed" \
    "grep -q 'applied' '$OUT/off.log' && ! R 'systemctl is-active kea' | grep -qx active && ! R 'test -e /etc/systemd/system/kea.service'"
check "off: nothing listens on 67, ufw's DHCP rule gone, the settings kept" \
    "! R 'ss -ulpn' | grep -q ':67 ' && ! R 'ufw status' | grep -q '67/udp' && R 'grep -q \"$LAB_NET\" /opt/fabric/config/vars.yaml'"
R "fabricctl dhcp on" > "$OUT/on2.log" 2>&1
check "on again: the kept settings served, no subnet asked for" "grep -q '$LAB_NET on $LAB_IF' '$OUT/on2.log' && R 'ss -ulpn' | grep -q '$LAB_ADDR:67 '"
check "$first: a lease again" "[ -n \"\$(renew $first)\" ]"

R 'fabricctl doctor' > "$OUT/doctor.log" 2>&1
check "doctor passes" "! grep -q '✗' '$OUT/doctor.log' && grep -q '✓' '$OUT/doctor.log'"
echo
echo "$PASS passed, $FAIL failed   (logs: $OUT)"
[ "$FAIL" -eq 0 ]
