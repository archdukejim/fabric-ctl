#!/bin/bash
# -----------------------------------------------------------------------
# The lab's dhcp campaign (manual 3.1.5.10; what it proves: 1.10.4.39). From Git Bash on gaming-23, after steps 1-4
# of 3.1.5.10 (the campaign started, the router's relay on, fabric installed on ub24-1 from tests/lab/dhcp_vars.yaml).
# No Python runs here (Windows' python is a store stub): every check runs on the lab VMs over SSH with the lab key.
#
#   tests/lab/dhcp_campaign.sh                 [ONLY="cli clients console" picks parts; all by default]
#
# The checks, each against the real router, Kea, BIND, the DC and the console:
#   the plan: VLAN 10 moved from the settings (1.10.4.37); VLAN 20 added from the CLI; Kea serving both
#   ping-check: an address that answers (the router's alias 10.88.10.100) is skipped and shown declined
#   the clients: kub26-1 (VLAN 10) and w11-1 (VLAN 20) leased through the relay, their names and PTRs in fabric's DNS
#   a reservation honoured; a name set by hand (--dns on) wins over DHCP's; Sync now publishes it
#   an option on a subnet reaching the client; a scan finding the unrecorded address; the plan poll taking a change
#   made without an apply within 30 s; the CLI's refusals; then the console (tests/lab/dhcp_console.py, on the VM)
# The router's alias is removed at the end; the VMs go back to `clean` afterwards (3.1.5.10, step 7).
# -----------------------------------------------------------------------
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
FABRIC=10.88.0.10; ROUTER=10.88.0.2; KUB=10.88.0.31; WIN=10.88.0.42
KUB_MAC=02:88:00:1f:00:02; WIN_IF="Ethernet 3"; DOMAIN=lab.test
ONLY="${ONLY:-cli clients console}"
OUT="${FABRIC_TEST_OUT:-/tmp/fabric-tests}/lab-dhcp-campaign"
SSH=(-i "$HOME/.ssh/g23_lab" -o "UserKnownHostsFile=$HOME/fabric-lab/known_hosts" -o BatchMode=yes -o ConnectTimeout=20)
PASS=0; FAIL=0
# Purpose: remove a scratch folder of this run. Never a path built from an empty variable, and only one under /tmp
#          (2.3.10.11.16: an empty variable once made `rm -f "$D"/*` remove WSL's / links).
clean_dir() {
    local d="${1:?clean_dir: no folder named}"
    case "$d" in /tmp/?*) ;; *) echo "refused: $d is not a folder under /tmp" >&2; exit 2 ;; esac
    case "$d" in *..*) echo "refused: $d climbs out of /tmp" >&2; exit 2 ;; esac
    rm -rf -- "$d"
}
clean_dir "$OUT"; mkdir -p "$OUT"
check() { if (set +o pipefail; eval "$2"); then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
# Purpose: a command on a lab VM: its output without OpenSSH's notices, and the command's own exit status.
on() {
    local out rc
    out=$(ssh "${SSH[@]}" "labadmin@$1" "$2" 2>&1); rc=$?
    printf '%s\n' "$out" | grep -v "post-quantum\|store now\|upgraded. See\|^$" || true
    return $rc
}
F() { on "$FABRIC" "sudo bash -lc $(printf '%q' "$1")"; }           # as root on the fabric VM
W() { on "$WIN" "powershell -NoProfile -Command \"$1\""; }            # on the Windows client
in_range() { # $1 address, $2 first, $3 last (same /24): whether first <= address <= last
    local a=${1##*.} f=${2##*.} l=${3##*.}
    [ "${1%.*}" = "${2%.*}" ] && [ "$a" -ge "$f" ] && [ "$a" -le "$l" ]
}
kea_has() { F "docker exec kea-dhcp4 cat /etc/kea/kea-dhcp4.conf" | grep -q "\"$1\""; }
kub_ip() { on "$KUB" "ip -4 -o addr show eth1 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | head -1"; }
kub_renew() { on "$KUB" "sudo networkctl renew eth1"; }
win_ip() { W "(Get-NetIPAddress -InterfaceAlias '$WIN_IF' -AddressFamily IPv4).IPAddress" | tr -d '\r' | head -1; }
dns() { F "dig +short $1 @$FABRIC" | tr -d '\r' | head -1; }
wait_for() { # $1 seconds, $2 condition (eval): true once it holds
    local i; for ((i = 0; i < $1; i += 3)); do (eval "$2") && return 0; sleep 3; done; return 1
}
SITE=$(F "python3 -c \"import yaml; print(yaml.safe_load(open('/opt/fabric/config/vars.yaml')).get('ad_site') or '')\"")
[ -n "$SITE" ] || SITE=$(F "fabricctl ipam show" | sed -n 's/^site \([^ :]*\).*/\1/p' | head -1)
echo "fabric's site: ${SITE:-unknown}"

if [[ " $ONLY " == *" cli "* ]]; then
echo "--- the plan from the CLI"
F "fabricctl ipam show" > "$OUT/show-1.txt"
check "VLAN 10's subnet from the settings is in the plan (the upgrade's move, 1.10.4.37)" "grep -q '10.88.10.0/24' '$OUT/show-1.txt'"
F "fabricctl ipam vlan add 20 --name vlan20 --subnet 10.88.20.0/24 --gateway 10.88.20.1" > "$OUT/vlan20.log" 2>&1
# covers: cli:ipam.vlan +
check "ipam vlan add 20: applied, its suggested ranges in the plan (DHCP .100-.249)" \
    "F 'fabricctl ipam show' | grep -q '10.88.20.100' && grep -qi 'applied' '$OUT/vlan20.log'"
check "Kea serves 10.88.10.0/24 and 10.88.20.0/24" "kea_has 10.88.10.0/24 && kea_has 10.88.20.0/24"
F "fabricctl ipam vlan add 20 --name again --subnet 10.88.21.0/24" > "$OUT/vlan20-again.log" 2>&1
# covers: cli:ipam.vlan -
check "a second VLAN 20 is refused, naming the first" "grep -qi 'vlan 20' '$OUT/vlan20-again.log' && ! kea_has 10.88.21.0/24"
F "fabricctl ipam address add 10.88.99.5 --kind reservation --mac 02:88:00:99:00:05 --name outside --vlan 10" \
    > "$OUT/outside.log" 2>&1
# covers: cli:ipam.address -
check "a reservation outside VLAN 10's subnet is refused, saying why, nothing written" \
    "grep -qi 'not in\|outside' '$OUT/outside.log' && ! F 'fabricctl ipam show' | grep -q 10.88.99.5"
F "fabricctl ipam range add 20 dhcp 10.88.20.1 10.88.20.20" > "$OUT/range-gw.log" 2>&1
# covers: cli:ipam.range -
check "a DHCP range over the gateway is refused" "grep -qi 'gateway\|overlap' '$OUT/range-gw.log'"
F "fabricctl ipam scan 192.168.1.0/24 --no-ask" > "$OUT/scan-other.log" 2>&1
# covers: cli:ipam.scan -
check "a scan of a network not in the plan is refused, probing nothing" "grep -qi 'not in' '$OUT/scan-other.log'"
F "fabricctl ipam sync --site elsewhere" > "$OUT/sync-site.log" 2>&1
# covers: cli:ipam.sync -
check "Sync now with --site is refused (a sync is the site's own)" "grep -qi 'own\|there' '$OUT/sync-site.log'"
fi

if [[ " $ONLY " == *" clients "* ]]; then
echo "--- ping-check: the router answers at 10.88.10.100, the pool's first address"
on "$ROUTER" "sudo ip addr add 10.88.10.100/24 dev vlans.10 2>/dev/null; true"
echo "--- kub26-1 on VLAN 10, through the relay"
on "$KUB" "sudo install -m 0600 /root/60-fabric-vlan10.yaml /etc/netplan/60-fabric-vlan10.yaml 2>/dev/null \
    || sudo cp /root/60-fabric-vlan10.yaml /etc/netplan/; sudo chmod 600 /etc/netplan/60-fabric-vlan10.yaml; sudo netplan apply"
wait_for 60 '[ -n "$(kub_ip)" ]'; KIP=$(kub_ip)
check "kub26-1: a lease from VLAN 10's pool through the relay ($KIP)" "in_range '$KIP' 10.88.10.100 10.88.10.199"
check "ping-check: 10.88.10.100 (answering) was not offered" "[ '$KIP' != 10.88.10.100 ]"
F "fabricctl dhcp leases" > "$OUT/leases-1.txt" 2>&1
check "ping-check: 10.88.10.100 shown declined in the leases" "grep 10.88.10.100 '$OUT/leases-1.txt' | grep -qi declin"
KNAME="g23-vm-kub26-1.dhcp.$DOMAIN"
check "kub26-1: its name $KNAME resolves to its lease, at fabric" "wait_for 30 '[ \"\$(dns $KNAME)\" = \"$KIP\" ]'"
check "kub26-1: its PTR names it" "wait_for 30 '[ \"\$(dns \"-x $KIP\")\" = \"$KNAME.\" ]'"
check "kub26-1: told fabric (host_ip) as its DNS server" "on $KUB 'resolvectl dns eth1' | grep -q '$FABRIC'"
echo "--- w11-1 on VLAN 20"
W "ipconfig /release '$WIN_IF' | Out-Null; ipconfig /renew '$WIN_IF' | Out-Null" > /dev/null 2>&1
wait_for 60 'in_range "$(win_ip)" 10.88.20.100 10.88.20.249'; WIP=$(win_ip)
check "w11-1: a lease from VLAN 20's pool through the relay ($WIP)" "in_range '$WIP' 10.88.20.100 10.88.20.249"
WNAME="g23-vm-w11-1.dhcp.$DOMAIN"
check "w11-1: its name $WNAME resolves to its lease" "wait_for 30 '[ \"\$(dns $WNAME)\" = \"$WIP\" ]'"
check "w11-1: its PTR names it" "wait_for 30 '[ \"\$(dns \"-x $WIP\")\" = \"$WNAME.\" ]'"
echo "--- a reservation, then a name set by hand"
F "fabricctl ipam address add 10.88.10.50 --kind reservation --mac $KUB_MAC --name kubres" > "$OUT/reserve.log" 2>&1
# covers: cli:ipam.address +
check "ipam address add (a reservation): applied" "grep -qi 'applied' '$OUT/reserve.log'"
kub_renew; on "$KUB" "sudo networkctl down eth1; sleep 2; sudo networkctl up eth1" >/dev/null
check "kub26-1 gets its reserved 10.88.10.50" "wait_for 60 '[ \"\$(kub_ip)\" = 10.88.10.50 ]'"
F "fabricctl ipam address set 10.88.10.50 --dns on --no-apply" > "$OUT/dns-on.log" 2>&1
F "fabricctl ipam sync" > "$OUT/sync.log" 2>&1
# covers: cli:ipam.sync +
check "Sync now publishes the name set by hand: kubres.$DOMAIN is 10.88.10.50" "wait_for 20 '[ \"\$(dns kubres.$DOMAIN)\" = 10.88.10.50 ]'"
check "its PTR is the name set by hand, not DHCP's" "[ \"\$(dns '-x 10.88.10.50')\" = 'kubres.$DOMAIN.' ]"
F "fabricctl dhcp clean-names" > "$OUT/clean.log" 2>&1
check "DHCP's name for it is gone from dhcp.$DOMAIN (1.10.4.19, 1.10.4.20)" "[ -z \"\$(dns $KNAME)\" ]"
echo "--- an option on VLAN 10's subnet reaches the client"
F "fabricctl ipam option set subnet vlan10 ntp-servers 10.88.0.10" > "$OUT/option.log" 2>&1
# covers: cli:ipam.option +
kub_renew
check "kub26-1's lease carries ntp-servers 10.88.0.10" \
    "wait_for 30 \"on $KUB 'cat /run/systemd/netif/leases/*' | grep -q 'NTP=10.88.0.10'\""
F "fabricctl ipam option show subnet vlan10" > "$OUT/option-show.log" 2>&1
check "option show subnet vlan10 names it, from the subnet" "grep ntp-servers '$OUT/option-show.log' | grep -q 10.88.0.10"
echo "--- a scan finds the unrecorded address"
F "fabricctl ipam scan vlan10 --no-ask" > "$OUT/scan.log" 2>&1
# covers: cli:ipam.scan +
check "the scan of vlan10 lists 10.88.10.100 as in use and unrecorded" "grep 10.88.10.100 '$OUT/scan.log' | grep -qi unrecorded"
echo "--- the plan poll takes a change made without an apply"
F "fabricctl ipam vlan add 40 --name vlan40 --subnet 10.88.40.0/24 --no-apply" > "$OUT/vlan40.log" 2>&1
check "not applied at once" "! kea_has 10.88.40.0/24"
check "the plan poll gives it to Kea within 30 s (45 allowed)" "wait_for 45 'kea_has 10.88.40.0/24'"
F "fabricctl ipam vlan remove 40" > /dev/null 2>&1
on "$ROUTER" "sudo ip addr del 10.88.10.100/24 dev vlans.10 2>/dev/null; true"
fi

if [[ " $ONLY " == *" console "* ]]; then
echo "--- the console, as three people (tests/lab/dhcp_console.py on the fabric VM)"
scp -q "${SSH[@]}" "$REPO/tests/lab/console_session.py" "$REPO/tests/lab/dhcp_console.py" \
    "$REPO/tests/sandbox/make_person.py" "$REPO/tests/host/reset_user.py" "labadmin@$FABRIC:/tmp/"
F "mkdir -p /root/lab && mv /tmp/console_session.py /tmp/dhcp_console.py /tmp/make_person.py /tmp/reset_user.py /root/lab/
   cd /root/lab && python3 make_person.py nora network-operators && python3 reset_user.py nora /root/nora-pw
   python3 make_person.py carol auditors && python3 reset_user.py carol /root/carol-pw" > "$OUT/people.log" 2>&1
F "cd /root/lab && python3 dhcp_console.py /opt/fabric/config/vars.yaml '$SITE'" | tee "$OUT/console.log"
PASS=$((PASS + $(grep -c '^PASS' "$OUT/console.log"))); FAIL=$((FAIL + $(grep -c '^FAIL' "$OUT/console.log")))
fi

F "fabricctl doctor" > "$OUT/doctor.log" 2>&1
check "doctor passes" "! grep -q '✗' '$OUT/doctor.log' && grep -q '✓' '$OUT/doctor.log'"
echo
echo "$PASS passed, $FAIL failed   (logs: $OUT)"
[ "$FAIL" -eq 0 ]
