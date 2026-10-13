#!/bin/bash
# -----------------------------------------------------------------------
# The 802.1X lab suite (manual 1.11.1.5, decision 2.1.11.7; the lab of 2.3.11.3 and 2.3.11.4): fabric's FreeRADIUS
# behind a real authenticator (hostapd, wired driver, dynamic VLANs) with a real Ubuntu supplicant (wpa_supplicant,
# wired driver). Run from a machine that reaches all three over SSH, by name:
#
#   SERVER=g23-vm-ub24-1 AUTH=debian-vswitch SUPPLICANT=g23-vm-ub22-1 \
#   AUTH_IP=10.20.0.5 PORT_IF=enp7s0 UPLINK_IF=enp8s0 SUP_IF=eth2 tests/lab/dot1x.sh
#   [PERSON=alice PERSON_PW_FILE=~/alice.pw: EAP-TTLS as a person of a mapped group]
#   [WINDOWS_MACHINE=HOST-1: W5 of 2.3.6.1.19, the Windows member's PEAP decisions]
#   [PRINTER_MAC=02:00:00:00:30:01 VLAN20_NET=10.20.20.0/24: a VLAN 20 lease expected from fabric's DHCP]
#
# SERVER has fabric installed with 802.1X on (install_freeradius: true); AUTH has hostapd; SUPPLICANT has
# wpa_supplicant and wpa_cli; AUTH_IP is the authenticator's address fabric sees. The suite adds a RADIUS client
# (lab-auth, generic), two device roles and two devices (lab-*), and removes them again at the end.
# Written 2026-10-12, NOT RUN (the owner's direction for 0.9; the Incus lab is not built: 2.3.11.2).
# -----------------------------------------------------------------------
set -uo pipefail
: "${SERVER:?ssh name of the fabric host}" "${AUTH:?ssh name of the authenticator}" \
  "${SUPPLICANT:?ssh name of the Ubuntu supplicant}" "${AUTH_IP:?the authenticator address fabric sees}"
PORT_IF="${PORT_IF:-enp7s0}"; UPLINK_IF="${UPLINK_IF:-enp8s0}"; SUP_IF="${SUP_IF:-eth2}"
PRINTER_MAC="${PRINTER_MAC:-02:00:00:00:30:01}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FABRIC_TEST_OUT:-/tmp/fabric-tests}/lab-dot1x"
LIB=/usr/lib/fabricctl/fabric/lib
PASS=0; FAIL=0
check() { if (set +o pipefail; eval "$2"); then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
# Purpose: run a command on a lab machine: its output without OpenSSH's notices, and the command's own exit status.
on() {
    local out rc
    out=$(ssh -o ConnectTimeout=20 "$1" "$2" 2>&1); rc=$?
    printf '%s\n' "$out" | grep -v "post-quantum\|store now\|upgraded. See\|^$" || true
    return $rc
}
R() { on "$SERVER" "sudo bash -lc $(printf '%q' "$1")"; }
# Purpose: the fixture (devices, roles, the device certificate) on the fabric host, with fabric's own functions.
fixture() { ssh -o ConnectTimeout=20 "$SERVER" "sudo PYTHONPATH=$LIB python3 - $*" < "$REPO/tests/lab/dot1x_fixture.py"; }
# Purpose: a file onto a lab machine from stdin, mode 0600, never through a command line.
put() { ssh -o ConnectTimeout=20 "$1" "umask 077; sudo install -m 0600 /dev/stdin $(printf '%q' "$2")"; }
rm -rf "$OUT"; mkdir -p "$OUT"; chmod 700 "$OUT"

SUP_MAC=$(on "$SUPPLICANT" "cat /sys/class/net/$SUP_IF/address")
DOMAIN=$(R "awk '/^domain:/ {print \$2}' /opt/fabric/config/vars.yaml" | tr -d '"')
FABRIC_IP=$(R "awk '/^host_ip:/ {print \$2}' /opt/fabric/config/vars.yaml" | tr -d '"')
check "802.1X is on at the fabric host" "R 'fabricctl radius status' | grep -q 'server name'"

echo "--- fabric: the authenticator as a RADIUS client (its secret shown once, kept in $OUT), roles, devices"
R "fabricctl radius remove-client lab-auth --no-apply" >/dev/null 2>&1
R "fabricctl radius add-client lab-auth $AUTH_IP --vendor generic" > "$OUT/add-client.log" 2>&1
SECRET=$(grep -A1 "shared secret (shown once" "$OUT/add-client.log" | tail -1)
check "the authenticator is added as a generic RADIUS client, its secret shown once" "[ \${#SECRET} -eq 32 ]"
( umask 077; fixture setup "$SUP_MAC" "$PRINTER_MAC" > "$OUT/cert.json" )
check "the fixture: roles lab-staff (EAP-TLS, VLAN 20) and lab-iot (MAB, VLAN 30), the devices, a certificate" \
      "python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert \"BEGIN CERTIFICATE\" in d[\"cert\"]' '$OUT/cert.json'"
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$OUT/cert.json" cert | put "$SUPPLICANT" /etc/lab-dot1x.crt
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$OUT/cert.json" key | put "$SUPPLICANT" /etc/lab-dot1x.key
R "cat /opt/fabric/stepca/data/certs/root_ca.crt" | put "$SUPPLICANT" /etc/lab-dot1x-ca.crt

echo "--- the authenticator: hostapd on $PORT_IF, dynamic VLANs tagged on $UPLINK_IF"
printf '%s\n' "interface=$PORT_IF" "driver=wired" "logger_syslog=-1" "logger_syslog_level=2" "ieee8021x=1" \
    "eap_reauth_period=3600" "use_pae_group_addr=1" "own_ip_addr=$AUTH_IP" "nas_identifier=lab-auth" \
    "auth_server_addr=$FABRIC_IP" "auth_server_port=1812" "auth_server_shared_secret=$SECRET" \
    "acct_server_addr=$FABRIC_IP" "acct_server_port=1813" "acct_server_shared_secret=$SECRET" \
    "radius_acct_interim_interval=60" "dynamic_vlan=1" "vlan_file=/etc/hostapd/lab-dot1x.vlan" \
    "vlan_tagged_interface=$UPLINK_IF" "vlan_bridge=brvlan" "ctrl_interface=/run/hostapd" \
    | put "$AUTH" /etc/hostapd/lab-dot1x.conf
printf '%s\n' "20 brvlan20" "30 brvlan30" "* brvlan#" | put "$AUTH" /etc/hostapd/lab-dot1x.vlan
on "$AUTH" "sudo pkill -f lab-dot1x.conf; sudo hostapd -B -P /run/lab-dot1x.pid /etc/hostapd/lab-dot1x.conf" >/dev/null
sleep 3
check "hostapd runs on the port" "on '$AUTH' 'pgrep -f lab-dot1x.conf' >/dev/null"

# Purpose: (re)start the supplicant with one network block (from stdin) and wait for its PAE state.
# Returns: 0 when AUTHENTICATED within 30 s.
supplicant() {
    put "$SUPPLICANT" /etc/lab-dot1x-wpa.conf
    on "$SUPPLICANT" "sudo pkill -f lab-dot1x-wpa.conf; sleep 1; sudo wpa_supplicant -B -D wired -i $SUP_IF \
        -c /etc/lab-dot1x-wpa.conf -C /run/lab-dot1x-wpa" >/dev/null
    for _ in $(seq 1 15); do
        sleep 2
        on "$SUPPLICANT" "sudo wpa_cli -p /run/lab-dot1x-wpa -i $SUP_IF status" | grep -q "Supplicant PAE state=AUTHENTICATED" \
            && return 0
    done
    return 1
}
TLS_CONF=$(printf '%s\n' "ctrl_interface=/run/lab-dot1x-wpa" "ap_scan=0" "network={" " key_mgmt=IEEE8021X" " eap=TLS" \
    " identity=\"lab-ubuntu\"" " ca_cert=\"/etc/lab-dot1x-ca.crt\"" " client_cert=\"/etc/lab-dot1x.crt\"" \
    " private_key=\"/etc/lab-dot1x.key\"" " domain_suffix_match=\"radius.$DOMAIN\"" " eapol_flags=0" "}")

echo "--- EAP-TLS"
check "EAP-TLS: the supplicant's certificate, linked to lab-ubuntu (lab-staff) -> the port opens" \
      "printf '%s\n' \"\$TLS_CONF\" | supplicant"
check "...fabric logged it accepted on VLAN 20" "R 'fabricctl radius log -n 20' | grep -qE 'ACCEPT +eap-tls +lab-ubuntu +vlan 20'"
check "...the authenticator put the port on VLAN 20 (brvlan20, tagged towards fabric)" \
      "on '$AUTH' 'ip -o link show master brvlan20' | grep -q '$PORT_IF'"
if [ -n "${VLAN20_NET:-}" ]; then
    check "...and the supplicant gets a lease in VLAN 20's subnet from fabric" \
          "on '$SUPPLICANT' 'sudo dhclient -1 -timeout 20 $SUP_IF; ip -4 -o addr show $SUP_IF' | python3 -c \
           \"import ipaddress,re,sys; a=re.findall(r'inet ([0-9.]+)/', sys.stdin.read()); \
             sys.exit(0 if a and ipaddress.ip_address(a[0]) in ipaddress.ip_network('$VLAN20_NET') else 1)\""
fi
check "accounting: the session is listed by fabric (fabricctl radius sessions)" \
      "sleep 5; R 'fabricctl radius sessions' | grep -q '$SUP_MAC'"
SESSION=$(R "fabricctl radius sessions" | awk -v m="$SUP_MAC" '$0 ~ m {print $2; exit}')
check "CoA refused for the generic authenticator, with why, nothing sent (1.11.1.4)" \
      "! R 'fabricctl radius disconnect lab-auth ${SESSION:-none}' 2>&1 | tee '$OUT/coa.log' >/dev/null; \
       grep -q 'does not know whether this switch accepts CoA' '$OUT/coa.log'"

echo "--- refusals"
fixture disable lab-ubuntu "$SUP_MAC" >/dev/null
check "a disabled device: the port stays closed" "! printf '%s\n' \"\$TLS_CONF\" | supplicant"
check "...fabric logged why" "R 'fabricctl radius log -n 20' | grep -qE 'REJECT +eap-tls +lab-ubuntu .*device disabled'"
fixture enable lab-ubuntu "$SUP_MAC" >/dev/null
if [ -n "${PERSON:-}" ] && [ -n "${PERSON_PW_FILE:-}" ]; then
    ttls_conf() {  # $1: the password
        printf '%s\n' "ctrl_interface=/run/lab-dot1x-wpa" "ap_scan=0" "network={" " key_mgmt=IEEE8021X" " eap=TTLS" \
            " identity=\"$PERSON\"" " anonymous_identity=\"anonymous\"" " password=\"$1\"" " phase2=\"auth=PAP\"" \
            " ca_cert=\"/etc/lab-dot1x-ca.crt\"" " domain_suffix_match=\"radius.$DOMAIN\"" " eapol_flags=0" "}"
    }
    check "EAP-TTLS: $PERSON (a mapped group) with their password -> the port opens" \
          "ttls_conf \"\$(cat '$PERSON_PW_FILE')\" | supplicant"
    check "EAP-TTLS: a wrong password -> the port stays closed" "! ttls_conf 'not-the-password-9' | supplicant"
fi

echo "--- a port with no supplicant, and MAB"
on "$SUPPLICANT" "sudo pkill -f lab-dot1x-wpa.conf" >/dev/null
check "no supplicant: the authenticator does not authorize the port" \
      "sleep 5; ! on '$AUTH' 'sudo hostapd_cli -p /run/hostapd -i $PORT_IF all_sta' | grep -q 'AUTHORIZED'"
printf '%s\n' "$SECRET" | put "$AUTH" /etc/hostapd/lab-dot1x.secret
mab() {  # $1: the MAC as a printer's switch port would send it; prints radclient's answer
    on "$AUTH" "printf 'User-Name = \"%s\", User-Password = \"%s\", Calling-Station-Id = \"%s\", \
        Message-Authenticator = 0x00\n' '${1//:/}' '${1//:/}' '$1' | sudo radclient -x -S /etc/hostapd/lab-dot1x.secret \
        -r 1 -t 5 $FABRIC_IP:1812 auth"
}
check "MAB by permission: lab-printer's MAC (lab-iot) -> accepted on VLAN 30" \
      "mab '$PRINTER_MAC' | grep -q 'Access-Accept' && mab '$PRINTER_MAC' | grep -qE 'Tunnel-Private-Group-Id.*30'"
check "MAB: a MAC no device has -> refused" "mab 02:00:00:00:99:99 | grep -q 'Access-Reject'"

if [ -n "${WINDOWS_MACHINE:-}" ]; then
    echo "--- W5 (2.3.6.1.19): the Windows member by PEAP, as itself, then a person"
    R "journalctl -t freeradius --since -1d --no-pager" > "$OUT/decisions.log"
    check "W5: $WINDOWS_MACHINE accepted by PEAP as itself at start-up" \
          "grep -F 'fabric: ACCEPT method=peap ' '$OUT/decisions.log' | grep -qiF ' machine=$WINDOWS_MACHINE\$ '"
    check "W5: a person accepted by PEAP after log-on" \
          "grep -F 'fabric: ACCEPT method=peap ' '$OUT/decisions.log' | grep -qF ' person='"
fi

echo "--- cleanup"
on "$AUTH" "sudo pkill -f lab-dot1x.conf; sudo rm -f /etc/hostapd/lab-dot1x.*" >/dev/null
on "$SUPPLICANT" "sudo rm -f /etc/lab-dot1x*" >/dev/null
fixture cleanup >/dev/null
R "fabricctl radius remove-client lab-auth" >/dev/null 2>&1
echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
