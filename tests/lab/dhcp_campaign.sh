#!/bin/bash
# -----------------------------------------------------------------------
# The lab's dhcp campaign (manual 3.1.5.10; what it proves: 1.10.4.39). From Git Bash on gaming-23, after steps 1-3
# of 3.1.5.10 (the campaign started, the router's relay on, fabric freshly installed on ub24-1 from
# tests/lab/dhcp_vars.yaml). No Python runs here (Windows' python is a store stub): every check runs on the lab VMs
# over SSH with the lab key.
#
#   tests/lab/dhcp_campaign.sh                 [ONLY="cli clients location console" picks parts; all by default]
#
# The checks, each against the real router, Kea, BIND, the DC and the console:
#   the plan: VLAN 10 moved from the settings (1.10.4.37); VLAN 20 added from the CLI; Kea serving both; the refusals
#   the clients: kub26-1 (VLAN 10) and w11-1 (VLAN 20) leased through the relay, their names and PTRs in fabric's DNS
#   ping-check: an address that answers (the router's alias 10.88.20.100) is skipped and shown declined
#   a scan finding that address; a reservation honoured; a name set by hand (--dns on) winning over DHCP's, published
#   by Sync now; an option on a subnet reaching the client; the plan poll taking a change made without an apply
#   the scan beyond a router (1.10.4.47): VLAN 20 is on none of fabric's networks, so its scan says "addresses only",
#   its find has no MAC, and is recorded both ways (a static address, then a reservation with the MAC typed)
#   a branch location's relayed subnet (1.10.4.46): VLAN 30 at location `branch`, kub26-1's VLAN NIC moved to VLAN 30
#   on Hyper-V (and back), leased through the relay; `ipam show` and the export name the location
#   then the console as three people (tests/lab/dhcp_console.py, on the fabric VM)
# The router's alias is removed at the end; the VMs go back to `clean` afterwards (3.1.5.10, step 7).
# -----------------------------------------------------------------------
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
FABRIC=10.88.0.10; ROUTER=10.88.0.2; KUB=10.88.0.31; WIN=10.88.0.42
KUB_MAC=02:88:00:1f:00:02; WIN_IF="Ethernet 3"; DOMAIN=lab.test
ONLY="${ONLY:-cli clients location console}"
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
    [ -n "$1" ] && [ "${1%.*}" = "${2%.*}" ] && [ "$a" -ge "$f" ] && [ "$a" -le "$l" ]
}
# Kea's config has // comments: grepped, not parsed
kea_has() { F "grep -q '\"subnet\": \"$1\"' /opt/kea/config/kea-dhcp4.conf"; }
kub_ip() { on "$KUB" "ip -4 -o addr show eth1 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | head -1"; }
kub_renew() { on "$KUB" "sudo networkctl reconfigure eth1" >/dev/null; }   # a new DISCOVER
win_ip() { W "(Get-NetIPAddress -InterfaceAlias '$WIN_IF' -AddressFamily IPv4).IPAddress" | tr -d '\r' | head -1; }
# Registrations are polled at BIND itself (10.255.0.30, the authoritative server): the filtering resolver at host_ip
# caches every answer, an early NXDOMAIN for 300 s (the DHCP zones' negative TTL), so polling it waits on its cache
# (2.3.10.11.16). Each client's name is resolved once through the resolver as well (rdns), after BIND has it.
BIND=10.255.0.30
dns() { F "dig +short $1 @$BIND" | tr -d '\r' | head -1; }
rdns() { F "dig +short $1 @$FABRIC" | tr -d '\r' | head -1; }
wait_for() { # $1 seconds, $2 condition (eval): true once it holds
    local i; for ((i = 0; i < $1; i += 3)); do (eval "$2") && return 0; sleep 3; done; return 1
}
# Purpose: the router's alias at VLAN 20's first pool address, which answers ping (ping-check, and the scan's find);
#          removed at the end, and by the router's checkpoint in any case.
alias_on() { on "$ROUTER" "sudo ip addr add 10.88.20.100/24 dev vlans.20 2>/dev/null; true" >/dev/null; }
alias_off() { on "$ROUTER" "sudo ip addr del 10.88.20.100/24 dev vlans.20 2>/dev/null; true" >/dev/null; }
SITE=$(F "python3 -c \"import yaml; print(yaml.safe_load(open('/opt/fabric/config/vars.yaml'))['site_name'])\"")
echo "fabric's site: ${SITE:-unknown}"

if [[ " $ONLY " == *" cli "* ]]; then
echo "--- the plan from the CLI"
alias_on    # before VLAN 20 is served: w11-1 asks for a lease on its own as soon as it is
F "fabricctl ipam show" > "$OUT/show-1.txt"
check "VLAN 10's subnet from the settings is in the plan (the upgrade's move, 1.10.4.37)" \
    "grep -q '^VLAN 10 .*10.88.10.0/24' '$OUT/show-1.txt'"
F "fabricctl ipam vlan add 20 --name vlan20 --subnet 10.88.20.0/24 --gateway 10.88.20.1" > "$OUT/vlan20.log" 2>&1
# covers: cli:ipam.vlan +
check "ipam vlan add 20: its suggested ranges (DHCP .100-.249), applied, the firewall in line" \
    "grep -q 'dhcp 10.88.20.100 - 10.88.20.249' '$OUT/vlan20.log' && grep -q '^applied' '$OUT/vlan20.log' \
     && grep -q 'host firewall: in line' '$OUT/vlan20.log'"
check "Kea serves 10.88.10.0/24 and 10.88.20.0/24" "kea_has 10.88.10.0/24 && kea_has 10.88.20.0/24"
F "fabricctl ipam vlan add 20 --name again --subnet 10.88.21.0/24" > "$OUT/vlan20-again.log" 2>&1
# covers: cli:ipam.vlan -
check "a second VLAN 20 is refused, naming the first; nothing served" \
    "grep -q \"VLAN 20 is already in this site's plan (vlan20)\" '$OUT/vlan20-again.log' && ! kea_has 10.88.21.0/24"
F "fabricctl ipam address add 10.88.99.5 --kind reservation --mac 02:88:00:99:00:05 --name outside --vlan 10" \
    > "$OUT/outside.log" 2>&1
# covers: cli:ipam.address -
check "a reservation outside VLAN 10's subnet is refused, saying why, nothing written" \
    "grep -q 'outside the subnet 10.88.10.0/24' '$OUT/outside.log' && ! F 'fabricctl ipam show' | grep -q 10.88.99.5"
F "fabricctl ipam range add 20 dhcp 10.88.20.1 10.88.20.20" > "$OUT/range-gw.log" 2>&1
# covers: cli:ipam.range -
check "a DHCP range over the gateway is refused" "grep -q 'overlaps the gateway range' '$OUT/range-gw.log'"
F "fabricctl ipam address add 10.88.10.1 --kind static --name gw2" > "$OUT/claim-gw.log" 2>&1
check "a static address on the gateway is refused, naming it" \
    "grep -q 'already claimed: it is the gateway' '$OUT/claim-gw.log'"
F "fabricctl ipam scan 192.168.1.0/24 --no-ask" > "$OUT/scan-other.log" 2>&1
# covers: cli:ipam.scan -
check "a scan of a network not in the plan is refused, naming the plan's" \
    "grep -q \"is not a subnet of this site's plan\" '$OUT/scan-other.log'"
F "fabricctl ipam sync --site elsewhere" > "$OUT/sync-site.log" 2>&1
# covers: cli:ipam.sync -
check "Sync now with --site is refused (a sync is the site's own)" "grep -q \"a sync is this site's own\" '$OUT/sync-site.log'"
F "fabricctl ipam block 0" > "$OUT/block0.log" 2>&1
# covers: cli:ipam.block -
check "site number 0 is refused" "grep -q 'a whole number from 1 to 255' '$OUT/block0.log'"
fi

if [[ " $ONLY " == *" clients "* ]]; then
echo "--- kub26-1 on VLAN 10 (its eth1 asks DHCP by itself: the image's zzzz-dracut-default.network)"
kub_renew; wait_for 60 'in_range "$(kub_ip)" 10.88.10.100 10.88.10.199'; KIP=$(kub_ip)
check "kub26-1: a lease from VLAN 10's pool through the relay ($KIP)" "in_range '$KIP' 10.88.10.100 10.88.10.199"
KNAME="g23-vm-kub26-1.dhcp.$DOMAIN"
check "kub26-1: its name $KNAME is registered at its lease, in BIND" "wait_for 30 '[ \"\$(dns $KNAME)\" = \"$KIP\" ]'"
check "kub26-1: its PTR names it" "wait_for 30 '[ \"\$(dns \"-x $KIP\")\" = \"$KNAME.\" ]'"
check "kub26-1: its name resolves through fabric's resolver (host_ip)" "[ \"\$(rdns $KNAME)\" = '$KIP' ]"
check "kub26-1: told fabric (host_ip) as its DNS server" "on $KUB 'resolvectl dns eth1' | grep -q '$FABRIC'"
echo "--- w11-1 on VLAN 20, the router answering at 10.88.20.100 (ping-check)"
alias_on
W "ipconfig /release '$WIN_IF' | Out-Null; ipconfig /renew '$WIN_IF' | Out-Null" > /dev/null 2>&1
wait_for 90 'in_range "$(win_ip)" 10.88.20.100 10.88.20.249'; WIP=$(win_ip)
check "w11-1: a lease from VLAN 20's pool through the relay ($WIP)" "in_range '$WIP' 10.88.20.100 10.88.20.249"
check "ping-check: 10.88.20.100, which answers, was not offered" "[ '$WIP' != 10.88.20.100 ]"
F "fabricctl dhcp leases" > "$OUT/leases.txt" 2>&1
check "ping-check: 10.88.20.100 shown declined in the leases" "grep '^10.88.20.100 ' '$OUT/leases.txt' | grep -q declined"
WNAME="g23-vm-w11-1.dhcp.$DOMAIN"
check "w11-1: its name $WNAME is registered at its lease, in BIND" "wait_for 30 '[ \"\$(dns $WNAME)\" = \"$WIP\" ]'"
check "w11-1: its name resolves through fabric's resolver (host_ip)" "[ \"\$(rdns $WNAME)\" = '$WIP' ]"
check "w11-1: its PTR names it" "wait_for 30 '[ \"\$(dns \"-x $WIP\")\" = \"$WNAME.\" ]'"
check "w11-1: told fabric (host_ip) as its DNS server" \
    "W \"(Get-DnsClientServerAddress -InterfaceAlias '$WIN_IF' -AddressFamily IPv4).ServerAddresses\" | grep -q '$FABRIC'"
echo "--- a scan finds the router's unrecorded address"
F "fabricctl ipam scan vlan20 --no-ask" > "$OUT/scan.log" 2>&1
# covers: cli:ipam.scan +
check "the scan of vlan20 lists 10.88.20.100 in use and unrecorded, and the command to record it" \
    "grep '10.88.20.100' '$OUT/scan.log' | grep -q 'IN USE, UNRECORDED' && grep -q 'ipam address add 10.88.20.100' '$OUT/scan.log'"
echo "--- the scan beyond a router (2.1.10.50, 1.10.4.47): fabric has no address in VLAN 20"
check "the scan says VLAN 20 is beyond a router: addresses only" \
    "grep -q 'beyond a router: addresses only' '$OUT/scan.log'"
check "the router's address is found with no MAC (ARP sees none past the gateway)" \
    "grep -E '^ +10\.88\.20\.100 +- ' '$OUT/scan.log' | grep -q 'IN USE, UNRECORDED'"
check "both ways to record it are printed: a static address, or a reservation once its MAC is known" \
    "grep -q 'ipam address add 10.88.20.100 --kind static' '$OUT/scan.log' \
     && grep -q 'ipam address add 10.88.20.100 --kind reservation --mac <MAC>' '$OUT/scan.log'"
F "fabricctl ipam address add 10.88.20.100 --kind reservation --name rtr20 --no-apply" > "$OUT/routed-nomac.log" 2>&1
check "a reservation of the find without its MAC is refused, recording nothing" \
    "grep -q 'a reservation needs the device' '$OUT/routed-nomac.log' && ! F 'fabricctl ipam show' | grep -q rtr20"
F "fabricctl ipam address add 10.88.20.100 --kind static --name rtr20 --no-apply" > "$OUT/routed-static.log" 2>&1
check "the find recorded as a static address" \
    "F 'fabricctl ipam show' | grep '10.88.20.100' | grep 'rtr20' | grep -q static"
F "fabricctl ipam address remove 10.88.20.100 --no-apply" > /dev/null 2>&1
RTR_MAC=$(on "$ROUTER" "cat /sys/class/net/vlans.20/address" | tr -d '\r' | head -1)
F "fabricctl ipam address add 10.88.20.100 --kind reservation --mac $RTR_MAC --name rtr20 --no-apply" \
    > "$OUT/routed-mac.log" 2>&1
check "the find recorded as a reservation once its MAC ($RTR_MAC) is typed" \
    "F 'fabricctl ipam show' | grep '10.88.20.100' | grep 'rtr20' | grep -q reservation"
F "fabricctl ipam address remove 10.88.20.100" > /dev/null 2>&1
echo "--- a reservation, then a name set by hand"
F "fabricctl ipam address add 10.88.10.50 --kind reservation --mac $KUB_MAC --name kubres" > "$OUT/reserve.log" 2>&1
# covers: cli:ipam.address +
check "ipam address add (a reservation): recorded and applied" \
    "grep -q '10.88.10.50 recorded (reservation)' '$OUT/reserve.log' && grep -q '^applied' '$OUT/reserve.log'"
kub_renew
check "kub26-1 gets its reserved 10.88.10.50" "wait_for 60 '[ \"\$(kub_ip)\" = 10.88.10.50 ]'"
check "the reservation's name kubres.dhcp.$DOMAIN is registered at 10.88.10.50, with its PTR" \
    "wait_for 30 '[ \"\$(dns kubres.dhcp.$DOMAIN)\" = 10.88.10.50 ] && [ \"\$(dns \"-x 10.88.10.50\")\" = kubres.dhcp.$DOMAIN. ]'"
check "kub26-1's old DHCP name is gone" "wait_for 30 '[ -z \"\$(dns $KNAME)\" ]'"
F "fabricctl ipam address set 10.88.10.50 --dns on --no-apply" > "$OUT/dns-on.log" 2>&1
F "fabricctl ipam sync" > "$OUT/sync.log" 2>&1
# covers: cli:ipam.sync +
check "Sync now publishes the name set by hand: kubres.$DOMAIN is 10.88.10.50" \
    "wait_for 20 '[ \"\$(dns kubres.$DOMAIN)\" = 10.88.10.50 ]'"
check "10.88.10.50's PTR is the name set by hand, not DHCP's" \
    "wait_for 20 '[ \"\$(dns \"-x 10.88.10.50\")\" = kubres.$DOMAIN. ]'"
kub_renew
F "fabricctl dhcp clean-names" > "$OUT/clean-names.log" 2>&1
check "DHCP's name for it is gone: kubres.dhcp.$DOMAIN (1.10.4.19, 1.10.4.20)" \
    "wait_for 30 '[ -z \"\$(dns kubres.dhcp.$DOMAIN)\" ]'"
echo "--- an option on VLAN 10's subnet reaches the client"
F "fabricctl ipam option set subnet vlan10 ntp-servers 10.88.0.10" > "$OUT/option.log" 2>&1
# covers: cli:ipam.option +
kub_renew
check "kub26-1's lease carries ntp-servers 10.88.0.10" \
    "wait_for 30 \"on $KUB 'cat /run/systemd/netif/leases/*' | grep -q '^NTP=10.88.0.10'\""
F "fabricctl ipam option show subnet vlan10" > "$OUT/option-show.log" 2>&1
check "option show subnet vlan10 names it" "grep ntp-servers '$OUT/option-show.log' | grep -q 10.88.0.10"
echo "--- the plan poll takes a change made without an apply"
F "fabricctl ipam vlan add 40 --name vlan40 --subnet 10.88.40.0/24 --no-apply" > "$OUT/vlan40.log" 2>&1
check "not served at once (--no-apply)" "! kea_has 10.88.40.0/24"
check "the plan poll gives it to Kea within 30 s (45 allowed)" "wait_for 45 'kea_has 10.88.40.0/24'"
F "fabricctl ipam vlan remove 40" > /dev/null 2>&1
alias_off
fi

if [[ " $ONLY " == *" location "* ]]; then
echo "--- a branch location's relayed subnet (2.1.10.48, 2.1.10.49; 1.10.4.46): VLAN 30 at location branch"
# kub26-1's VLAN NIC (its MAC $KUB_MAC) moves to VLAN 30 on Hyper-V for this part, and back to VLAN 10 at its end;
# the VM's checkpoint (3.1.5.10, step 7) holds VLAN 10 as well.
kub_vlan() { # $1 the VLAN ID for kub26-1's VLAN NIC
    local mac; mac=$(echo "$KUB_MAC" | tr -d ':' | tr 'a-f' 'A-F')
    powershell.exe -NoProfile -Command "Get-VMNetworkAdapter -VMName g23-vm-kub26-1 | Where-Object MacAddress -eq '$mac' | Set-VMNetworkAdapterVlan -Access -VlanId $1" > /dev/null
}
KNAME="g23-vm-kub26-1.dhcp.$DOMAIN"
trap 'kub_vlan 10' EXIT
F "fabricctl ipam vlan add 30@branch --name vlan30 --subnet 10.88.30.0/24 --gateway 10.88.30.1" > "$OUT/vlan30.log" 2>&1
# covers: cli:ipam.vlan +
check "ipam vlan add 30@branch: applied, its suggested DHCP range .100-.249" \
    "grep -q 'dhcp 10.88.30.100 - 10.88.30.249' '$OUT/vlan30.log' && grep -q '^applied' '$OUT/vlan30.log'"
check "Kea serves the branch's 10.88.30.0/24" "kea_has 10.88.30.0/24"
F "fabricctl ipam show" > "$OUT/show-loc.txt"
check "ipam show lists VLAN 30 under 'at branch', its subnet named branch-vlan30" \
    "grep -q 'at branch' '$OUT/show-loc.txt' && grep -q 'branch-vlan30' '$OUT/show-loc.txt'"
F "fabricctl ipam vlan add 30@branch --name again --subnet 10.88.31.0/24" > "$OUT/vlan30-again.log" 2>&1
# covers: cli:ipam.vlan -
check "a second VLAN 30 at branch is refused; nothing served" \
    "grep -q 'already' '$OUT/vlan30-again.log' && ! kea_has 10.88.31.0/24"
kub_vlan 30; kub_renew
wait_for 90 'in_range "$(kub_ip)" 10.88.30.100 10.88.30.249'; BIP=$(kub_ip)
check "kub26-1 at the branch: a lease from 10.88.30.0/24 through the router's relay ($BIP)" \
    "in_range '$BIP' 10.88.30.100 10.88.30.249"
check "its name $KNAME is registered at the branch's address, in BIND" \
    "wait_for 30 '[ \"\$(dns $KNAME)\" = \"$BIP\" ]'"
F "fabricctl ipam export" > "$OUT/export-loc.csv" 2>&1
check "the export's last column is location (2.1.10.52), the branch's rows ending in branch" \
    "head -1 '$OUT/export-loc.csv' | grep -q ',location$' && grep '10.88.30.1,' '$OUT/export-loc.csv' | grep -q ',branch$'"
kub_vlan 10; trap - EXIT; kub_renew
F "fabricctl ipam vlan remove 30@branch --force" > "$OUT/vlan30-remove.log" 2>&1
check "VLAN 30 at branch removed; Kea no longer serves it; kub26-1 back on VLAN 10" \
    "! kea_has 10.88.30.0/24 && wait_for 60 'in_range \"\$(kub_ip)\" 10.88.10.0 10.88.10.255'"
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
