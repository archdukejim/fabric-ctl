#!/bin/bash
# -----------------------------------------------------------------------
# End-to-end test of the product as users get it, in a disposable
# systemd + Docker sandbox (Ubuntu 24.04, no git checkout inside):
#   apt install ./fabricctl_<v>_all.deb -> fabricctl setup --file vars.yaml
#   -> doctor, DHCP (Kea), 802.1X (FreeRADIUS), the certificate page,
#   systemd control (fabric.target), secrets and unlock in OpenBao, real
#   sign-in incl. refusals, image update/rollback/prune, RFC2136/TSIG/ACLs,
#   re-runs, package upgrade and remove, reinstall, uninstall with export,
#   restore from the export
#
#   sudo tests/sandbox/run.sh            (KEEP=1 leaves the sandbox running)
#
# The sandbox has its own Docker daemon, network and ports, so it does not
# touch the host's containers. Needs privileged Docker on the host.
# -----------------------------------------------------------------------
set -uo pipefail
exec 9>/tmp/fabric-sandbox-suite.lock
flock -n 9 || { echo "another sandbox run is active; refusing to start" >&2; exit 2; }
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FABRIC_TEST_OUT:-/tmp/fabric-tests}/sandbox"
NAME=fabric-sandbox
NET=fabric-sbx-net
SUBNET=10.77.0.0/24
IP=10.77.0.10
PASS=0; FAIL=0
# Checks run without pipefail: `cmd | grep -q x` must not fail when grep
# finds x early and cmd then gets SIGPIPE writing the rest of its output.
check() { if (set +o pipefail; eval "$2"); then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
in_box() { docker exec "$NAME" bash -lc "$*"; }

docker rm -f "$NAME" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1
docker volume rm fabric-sbx-docker >/dev/null 2>&1
rm -rf "$OUT"; mkdir -p "$OUT"

docker build -q -t fabric/sandbox:local "$REPO/tests/sandbox" >/dev/null || { echo "FAIL sandbox image"; exit 1; }
docker network create --subnet "$SUBNET" --gateway 10.77.0.1 "$NET" >/dev/null
# cgroupns=private and NO host /sys/fs/cgroup mount: the sandbox's systemd
# must never see the host's cgroup tree. With cgroupns=host its
# docker.service shared the host's cgroup, and restarting Docker inside the
# sandbox killed the host's dockerd.
docker run -d --name "$NAME" --hostname fabric-sbx --privileged --cgroupns=private \
  -v fabric-sbx-docker:/var/lib/docker \
  --tmpfs /run --tmpfs /run/lock --network "$NET" --ip "$IP" fabric/sandbox:local >/dev/null
for _ in $(seq 1 30); do in_box 'systemctl is-system-running 2>/dev/null' | grep -qE 'running|degraded' && break; sleep 2; done
# Nested Docker only: containerd's image store cannot unpack layers inside a
# container ("failed to convert whiteout file"); use the classic overlay2
# store. fabricctl merges its hardening into this file, so it survives.
in_box 'mkdir -p /etc/docker && echo "{\"features\": {\"containerd-snapshotter\": false}, \"storage-driver\": \"overlay2\"}" > /etc/docker/daemon.json'

# The package, built from the working tree exactly as a release would be.
DEB=$(OUT="$OUT/dist" bash "$REPO/packaging/deb/build-deb.sh") || { echo "FAIL package build"; exit 1; }
docker cp "$DEB" "$NAME:/root/fabricctl.deb"
echo "--- apt install ./$(basename "$DEB")"
in_box 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /root/fabricctl.deb' > "$OUT/apt.log" 2>&1
check "package installs with apt (dependencies resolved)" "in_box 'dpkg -s fabricctl' | grep -q '^Status: install ok installed'"
check "fabricctl is the packaged command" "in_box 'command -v fabricctl' | grep -qx /usr/bin/fabricctl"
check "installing the package started nothing" "! in_box 'test -e /etc/systemd/system/fabric.target'"
# (the command exits 1 here by design; `; true` keeps pipefail from masking grep)
check "before setup, day-2 commands say what to do" "in_box 'fabricctl status 2>&1; true' | grep -q 'not set up on this host yet'"
# An existing TSIG key (as on a host being rebuilt) whose RFC2136 client —
# nginx-proxy-manager's certbot plugin — must keep working unchanged.
TSIG_SECRET=$(openssl rand -base64 32)
cat > "$OUT/vars.yaml" <<EOF
domain: lan.test
hostname: fabric-sbx
host_ip: $IP
lan_cidr: $SUBNET
lan_gateway: 10.77.0.1
friendly_name: Sandbox
ad_domain: ad.test
ad_password_policy: {minimum_length: 14, complexity: true, history: 24, minimum_age_days: 0, maximum_age_days: 0, lockout_threshold: 10, lockout_minutes: 15, lockout_window_minutes: 15}
install_keycloak: true
install_webui: true
# the raised sign-in (2.3.6.2.6): the strict login test below; the host suite proves the default and raising
webui_client_cert: true
signin_admin_second_factor: totp
install_freeradius: true
install_kea: true
dns_filter: bind
ntp_set_clock: false        # the sandbox shares the PC's kernel clock: chrony keeps time, never sets it
dhcp:
  interfaces: [eth0]
  lease_time: 600
  subnets:
    - subnet: $SUBNET
      pools: ["10.77.0.200 - 10.77.0.220"]
      routers: 10.77.0.1
tsig_keys:
- { name: npm, records: [npm], secret: "$TSIG_SECRET", acls: [npm-updaters] }
EOF
docker cp "$OUT/vars.yaml" "$NAME:/root/vars.yaml"

echo "--- setup (fresh install)"
# the first admin's password, chosen for this run and handed over in a file (2.1.6.33: never on a command line)
ADMIN_PW="Fx9-$(openssl rand -hex 12)"
( umask 077; printf '%s\n' "$ADMIN_PW" > "$OUT/admin-pw"; printf 'short\n' > "$OUT/admin-pw-short" )
docker cp "$OUT/admin-pw" "$NAME:/root/admin-pw"; docker cp "$OUT/admin-pw-short" "$NAME:/root/admin-pw-short"
in_box 'fabricctl setup --file /root/vars.yaml --non-interactive --yes --approve all' > "$OUT/setup-nopw.log" 2>&1
check "unattended setup without the first admin's password refuses before any step, naming --admin-password-file" \
    "grep -q 'needs a password: --admin-password-file' '$OUT/setup-nopw.log' && ! grep -q '\[preflight\]' '$OUT/setup-nopw.log' \
     && ! in_box 'getent passwd fabric-dns'"
in_box 'fabricctl setup --file /root/vars.yaml --non-interactive --yes --approve all --admin-password-file /root/admin-pw-short' \
    > "$OUT/setup-shortpw.log" 2>&1
check "a password the domain's policy refuses is refused before any step, saying why" \
    "grep -q 'admin-pw-short is refused: at least' '$OUT/setup-shortpw.log' && ! grep -q '\[preflight\]' '$OUT/setup-shortpw.log'"
in_box 'fabricctl setup --file /root/vars.yaml --non-interactive --yes --admin-password-file /root/admin-pw' \
    > "$OUT/setup-noconsent.log" 2>&1
check "unattended setup without --approve changes nothing and names the groups to answer" \
    "grep -q 'need an answer: packages' '$OUT/setup-noconsent.log' && ! in_box 'test -e /etc/systemd/system/fabric.target' \
     && ! in_box 'getent passwd fabric-dns'"
in_box 'fabricctl setup --file /root/vars.yaml --non-interactive --yes --approve all --admin-password-file /root/admin-pw' 2>&1 \
    | tee "$OUT/setup.log"
check "setup completes" "grep -q 'fabric is ready' '$OUT/setup.log'"
check "the first admin is fabric-admin, created with the password chosen for setup (2.1.6.33)" \
    "grep -q \"admin 'fabric-admin' created in the directory with the password chosen in setup\" '$OUT/setup.log'"
check "Kerberos sign-in is off on an unattended new install (2.1.6.32)" \
    "in_box 'grep -qx \"signin_kerberos: false\" /opt/fabric/config/vars.yaml'"
grep -q "fabric is ready" "$OUT/setup.log" || in_box 'journalctl --no-pager -u samba | tail -60; docker logs samba 2>&1 | tail -80' > "$OUT/setup-dc.log" 2>&1   # diagnosis when setup fails
check "setup did not shadow the package command" "! in_box 'test -e /usr/local/bin/fabricctl'"
check "setup wrote nothing beside the package's copy: its records are the install's (0.6.4)" \
    "! in_box 'test -e /usr/lib/fabricctl/fabric/archive || test -e /usr/lib/fabricctl/fabric/config'"
check "Docker comes from the Ubuntu archive, no apt source added" \
    "in_box 'dpkg -s docker.io docker-compose-v2 docker-buildx' | grep -c '^Status: install ok installed' | grep -qx 3 \
     && ! in_box 'ls /etc/apt/sources.list.d/' | grep -qv '^ubuntu.sources$'"

echo "--- doctor"
in_box 'fabricctl doctor' 2>&1 | tee "$OUT/doctor.log"
check "doctor: all checks pass" "! grep -q '✗' '$OUT/doctor.log' && grep -q '✓' '$OUT/doctor.log'"

echo "--- fabric's own images (manual 1.14.3): published and signature-checked once the lock pins them"
published=$(PYTHONPATH="$REPO/src" python3 -c "from fabriclib.common.read_published_lock import read_published_lock as r
print(sum(1 for e in r('$REPO/config')['images'].values() if e['ref']))")
# how many images fabric publishes (7 since 0.7: AdGuard's went with it, 2.1.12.3)
total=$(PYTHONPATH="$REPO/src" python3 -c "from fabriclib.common.read_published_lock import read_published_lock as r
print(len(r('$REPO/config')['images']))")
if [ "$published" -eq "$total" ]; then
    check "the core services run fabric's published images (pulled, not built here)" \
        "in_box 'docker inspect -f {{.Config.Image}} bind9 samba keycloak step-ca fabric-web' \
         | grep -c '^ghcr.io/archdukejim/open-fabric/' | grep -qx 5 && ! in_box 'docker image inspect fabric/bind9:local' >/dev/null 2>&1"
    check "each was signature-checked before use (verified digests remembered, root-only)" \
        "in_box 'stat -c %a /etc/fabric/images/verified.json' | grep -qx 600 \
         && [ \"\$(in_box \"grep -cE '^ +.at.: ' /etc/fabric/images/verified.json\")\" -ge 5 ]"
else
    # some published, some still pending (new or rebuilt on this branch, 3.14.1.4): the pending ones are built here
    pending=$(PYTHONPATH="$REPO/src" python3 -c "from fabriclib.common.read_published_lock import read_published_lock as r
print(' '.join('fabric/' + {'webui': 'web'}.get(n, n) + ':local' for n, e in r('$REPO/config')['images'].items() if not e['ref']))")
    check "$published of $total published: the pending ones are built here ($pending)" \
        "in_box 'docker image inspect $pending' >/dev/null"
fi
check "fabricctl status lists the relaxed security settings (none here)" \
    "in_box 'fabricctl status' | grep -A1 '^relaxed security settings:' | grep -qx '  none'"

echo "--- undoing one host change (manual 1.2.9.5): trust, then approved again"
UFW_BEFORE=$(in_box 'cat /opt/fabric/config/host-originals/ufw.state' 2>/dev/null)
check "the host's own files were kept before fabric first changed them (chrony's, ufw's state)" \
    "in_box 'test -f /opt/fabric/config/host-originals/etc/chrony/chrony.conf' && ! in_box 'grep -q \"^# fabric\" /opt/fabric/config/host-originals/etc/chrony/chrony.conf' && [ -n '$UFW_BEFORE' ]"
in_box 'fabricctl setup --undo trust --non-interactive' > "$OUT/undo-refused.log" 2>&1
check "setup --undo unattended without --yes changes nothing" \
    "grep -q 'pass --yes' '$OUT/undo-refused.log' && in_box 'ls /usr/local/share/ca-certificates/fabric-*' >/dev/null 2>&1"
in_box 'fabricctl setup --undo trust --non-interactive --yes' > "$OUT/undo-trust.log" 2>&1
check "setup --undo trust: fabric's CA out of the host trust store, recorded as declined (status shows it)" \
    "! in_box 'ls /usr/local/share/ca-certificates/fabric-*' >/dev/null 2>&1 && in_box 'fabricctl status' | grep -qE '^  trust +declined'"
in_box 'fabricctl doctor' > "$OUT/doctor-undo.log" 2>&1
check "doctor passes with trust declined (it no longer expects the host to trust the CA)" \
    "! grep -q '✗' '$OUT/doctor-undo.log' && ! grep -q 'this host trusts the fabric CA' '$OUT/doctor-undo.log'"
in_box 'fabricctl setup --approve trust --step pki --non-interactive --yes' > "$OUT/undo-reapprove.log" 2>&1
check "setup --approve trust puts the CA back in the host trust store" \
    "in_box 'ls /usr/local/share/ca-certificates/fabric-*' >/dev/null 2>&1 && in_box 'fabricctl status' | grep -qE '^  trust +approved'"
in_box 'fabricctl setup --undo accounts --non-interactive --yes' > "$OUT/undo-accounts.log" 2>&1
check "setup --undo refuses what fabric needs (accounts), naming uninstall" "grep -q 'fabricctl uninstall' '$OUT/undo-accounts.log'"

echo "--- POSIX identities in the domain (manual 1.6.3.9)"
check "the admin has fabric's POSIX identity in AD: a uid from the site's block, Domain Users' gid 5000" \
    "in_box \"docker exec samba ldbsearch -H /data/private/sam.ldb '(sAMAccountName=fabric-admin)' uidNumber gidNumber\" | grep -qE '^uidNumber: (500[1-9]|50[1-9][0-9]|5[1-9][0-9]{2}|[1-9][0-9]{4,5})$'"

echo "--- traffic stays on the host (2.1.2.15): containers reach the DC on fabric_net's gateway"
DC_NAME=$(in_box "python3 -c 'import yaml; print(yaml.safe_load(open(\"/opt/fabric/config/vars.yaml\"))[\"hostname_dc\"])'")
check "the DC listens for LDAPS on fabric_net's gateway (10.255.0.1) as well as the LAN address"     "in_box 'ss -ltn' | grep -q '10.255.0.1:636' && in_box 'ss -ltn' | grep -q '$IP:636'"
check "Keycloak's LDAP federation and FreeRADIUS's LDAPS go to the gateway, never the LAN address" "in_box \"docker exec postgres psql -tA -U fabric_admin -d keycloak -c \\\"SELECT value FROM component_config WHERE name = 'connectionUrl'\\\"\" | grep -qx 'ldaps://10.255.0.1:636' && { ! in_box 'systemctl is-enabled freeradius' >/dev/null 2>&1 || in_box 'grep -q ldaps://10.255.0.1:636 /opt/freeradius/config/fabric-radius.json'; }"
check "the DC's name in DNS is the LAN address only (the gateway it listens on never published)"     "[ \"\$(in_box 'dig +short @$IP $DC_NAME A' | sort -u)\" = '$IP' ]"

echo "--- DNS filter (the BIND resolver) in front of BIND"
BIND_PORT=5053                      # dns_filter: bind moves BIND off 53
check "the resolver answers clients on 53 (fabric's names through BIND); BIND answers on 5053" \
    "in_box 'dig +short +time=3 @$IP ns.lan.test' | grep -qx $IP && in_box 'dig +short +time=3 -p 5053 @$IP ns.lan.test' | grep -qx $IP"
check "the resolver runs with no capabilities, as its own account" \
    "[ \"\$(in_box \"docker inspect -f '{{.HostConfig.CapAdd}} {{.HostConfig.CapDrop}} {{.Config.User}}' bind9-resolver\")\" = '[] [ALL] 613:613' ]"
check "fabricctl status lists the DNS filter" "in_box 'fabricctl status' | grep -qE '^bind9-resolver +active'"
check "fabricctl dns-filter status: the resolver answers and every list has a good copy" \
    "in_box 'fabricctl dns-filter status' > '$OUT/dns-filter-status.log' 2>&1"
check "the daily list timer is installed and enabled" "in_box 'systemctl is-enabled fabric-dns-lists.timer' | grep -qx enabled"
RES_SINCE=$(in_box 'systemctl show -p ActiveEnterTimestampMonotonic --value bind9-resolver')
in_box 'systemctl restart bind9' > /dev/null 2>&1
check "a BIND restart (every DNS apply) leaves the resolver running" \
    "[ \"\$(in_box 'systemctl show -p ActiveEnterTimestampMonotonic --value bind9-resolver')\" = '$RES_SINCE' ] && in_box 'systemctl is-active bind9-resolver' | grep -qx active"

echo "--- Time: chrony on the host serves the LAN (manual 1.13.1)"
BUSYBOX="busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
check "time: chrony runs, configured by fabric, answering the LAN" \
    "in_box 'systemctl is-active chrony' | grep -qx active && in_box 'grep -q ^allow /etc/chrony/chrony.conf && grep -q fabric /etc/chrony/chrony.conf'"
check "time: UDP 123 opened in the host firewall" "in_box 'ufw status' | grep -q '123/udp'"
check "time: ntp.lan.test points at the host" "in_box 'dig +short @$IP ntp.lan.test' | grep -qx $IP"
docker run --rm --network "$NET" "$BUSYBOX" timeout 20 ntpd -n -w -d -p "$IP" > "$OUT/ntp-client.log" 2>&1
check "time: a LAN client gets the time from the host" "grep -q 'reply from $IP' '$OUT/ntp-client.log'"

echo "--- DHCP: Kea 3.0 serves the LAN, lease hostnames in dhcp.<domain>"
docker rm -f fabric-sbx-dhcp >/dev/null 2>&1
# the event script prints what the client was handed (ntpsrv: DHCP option 42)
docker run --name fabric-sbx-dhcp --network "$NET" --cap-add NET_ADMIN --cap-add NET_RAW \
    -e EV='echo "event $1 ntpsrv=$ntpsrv"' "$BUSYBOX" \
    sh -c 'printf "#!/bin/sh\n%s\n" "$EV" > /tmp/ev && chmod +x /tmp/ev && exec udhcpc -i eth0 -n -q -f -t 5 -s /tmp/ev -O ntpsrv -x hostname:sbxclient' \
    > "$OUT/dhcp.log" 2>&1
docker rm -f fabric-sbx-dhcp >/dev/null 2>&1
check "kea: DHCP unit active, Kea 3.0 LTS inside" \
    "in_box 'systemctl is-active kea' | grep -qx active && in_box 'docker exec kea-dhcp4 kea-dhcp4 -v' | grep -q '^3\.0\.'"
check "kea: a LAN client gets an address from the pool" "grep -q 'lease of 10.77.0.2[0-2][0-9]' '$OUT/dhcp.log'"
check "kea: the client is handed this host as its time server (option 42)" "grep -q 'ntpsrv=$IP' '$OUT/dhcp.log'"
check "kea: its hostname is registered in dhcp.lan.test (delegated from lan.test)" \
    "for _ in 1 2 3 4 5; do in_box 'dig +short @$IP sbxclient.dhcp.lan.test' | grep -q '^10\.77\.0\.2' && exit 0; sleep 2; done; exit 1"
check "kea: fabricctl dhcp leases lists the client's lease" "in_box 'fabricctl dhcp leases' | grep -q 'sbxclient.dhcp.lan.test'"
in_box 'fabricctl dhcp reserve 02:00:00:00:77:01 10.77.0.50 sbxprinter' > "$OUT/dhcp-reserve.log" 2>&1
check "kea: fabricctl dhcp reserve saves and applies; status lists it"     "grep -q 'applied' '$OUT/dhcp-reserve.log' && in_box 'fabricctl dhcp status' | grep -q '02:00:00:00:77:01  10.77.0.50'"
check "kea: a reservation inside the pool is refused"     "! in_box 'fabricctl dhcp reserve 02:00:00:00:77:02 10.77.0.205 --no-apply' >/dev/null 2>&1"
# DHCP management (manual 1.10.2): subnets with name/VLAN/notes, options, a client class, Kea's own check
in_box 'fabricctl dhcp add-subnet 10.78.0.0/24 --name lab2 --vlan 78 --router 10.78.0.1 --pool "10.78.0.100 - 10.78.0.150" --notes "second lab"' > "$OUT/dhcp-subnet.log" 2>&1
in_box 'fabricctl dhcp class add pxe-uefi --test "option[93].hex == 0x0007" --next-server 10.77.0.30 --boot-file ipxe.efi' >> "$OUT/dhcp-subnet.log" 2>&1
in_box 'fabricctl dhcp option set tftp-server-name 10.77.0.30 --class pxe-uefi' >> "$OUT/dhcp-subnet.log" 2>&1
check "kea: add-subnet, a client class and an option are saved, applied, and Kea runs them" \
    "grep -c 'applied' '$OUT/dhcp-subnet.log' | grep -qx 3 && in_box 'systemctl is-active kea' | grep -qx active \
     && in_box 'fabricctl dhcp status' | grep -q 'lab2.*VLAN 78' && in_box 'cat /opt/kea/config/kea-dhcp4.conf' | grep -q 'pxe-uefi'"
in_box 'fabricctl dhcp option set no-such-option 1' > "$OUT/dhcp-badopt.log" 2>&1
check "kea: an option Kea does not know is refused before it is saved; the next apply is clean" \
    "grep -q 'Kea refused' '$OUT/dhcp-badopt.log' && ! in_box 'grep -q no-such-option /opt/fabric/config/vars.yaml' \
     && in_box 'fabricctl --apply' > '$OUT/dhcp-apply.log' 2>&1"
in_box 'fabricctl dhcp remove-subnet lab2 && fabricctl dhcp class remove pxe-uefi' > "$OUT/dhcp-remove.log" 2>&1
check "kea: remove-subnet and class remove apply; the first subnet keeps its id (its leases stay)" \
    "grep -c 'applied' '$OUT/dhcp-remove.log' | grep -qx 2 && in_box 'cat /opt/kea/config/kea-dhcp4.conf' | grep -qF '\"id\": 1,' \
     && in_box 'fabricctl dhcp leases' | grep -q 'sbxclient.dhcp.lan.test'"
echo "--- 802.1X: FreeRADIUS answers a switch from the directory"
in_box 'fabricctl radius add-client sbxswitch 10.77.0.1' > "$OUT/radius-add.log" 2>&1
RADIUS_SECRET=$(grep -A1 'shown once' "$OUT/radius-add.log" | tail -1)
docker cp "$REPO/tests/sandbox/radius_device.py" "$NAME:/root/radius_device.py"
docker cp "$REPO/tests/sandbox/list_roles.py" "$NAME:/root/list_roles.py"
check "setup created the six default device roles, once (marker)"     "in_box 'test -f /opt/fabric/config/.default-device-roles' && [ \"\$(in_box 'python3 /root/list_roles.py' | sort | tr '\n' ' ')\" = 'iot network-gear phones-tablets printers servers workstations ' ]"
check "the network groups exist and are mapped for password logins (no VLAN yet)"     "in_box 'fabricctl radius status' | grep -q 'group network-staff' && in_box 'fabricctl radius status' | grep -q 'group network-guests'"
check "radius: add-client applied; the secret is shown once and kept in OpenBao, not in vars"     "grep -q 'applied' '$OUT/radius-add.log' && [ \${#RADIUS_SECRET} -eq 32 ] && ! in_box \"grep -qF '$RADIUS_SECRET' /opt/fabric/config/vars.yaml\""
check "radius: a device with network:mab (made like the 389-DS tab does)"     "in_box 'python3 /root/radius_device.py 02:00:00:00:88:01' | grep -qx ok"
check "radius: the switch's MAB request for it -> Access-Accept on its role's VLAN"     "echo '$RADIUS_SECRET' | python3 '$REPO/tests/sandbox/radius_mab.py' $IP 02:00:00:00:88:01 | grep -qx 'Access-Accept vlan=30'"
check "radius: an unknown MAC -> Access-Reject"     "echo '$RADIUS_SECRET' | python3 '$REPO/tests/sandbox/radius_mab.py' $IP 02:00:00:00:88:99 | grep -qx 'Access-Reject'"
check "radius: a wrong shared secret gets no answer"     "echo 'NotTheSecretNotTheSecret' | python3 '$REPO/tests/sandbox/radius_mab.py' $IP 02:00:00:00:88:01 | grep -qx 'no reply'"
check "radius: fabricctl radius log shows both decisions"     "in_box 'fabricctl radius log' | grep -q 'ACCEPT mab .*sbxprinter .*vlan 30' && in_box 'fabricctl radius log' | grep -q 'REJECT mab'"
in_box 'fabricctl radius map-group auditors --vlan 40' > "$OUT/radius-map.log" 2>&1
check "radius: map-group applied; FreeRADIUS back up with EAP-TTLS on; status lists the group"     "grep -q applied '$OUT/radius-map.log' && in_box 'systemctl is-active freeradius' | grep -qx active && in_box 'grep -q \"ttls {\" /opt/freeradius/config/mods/eap' && in_box 'fabricctl radius status' | grep -q 'group auditors .*vlan 40'"
check "kea: fabricctl images status covers the Kea image" "in_box 'fabricctl images status' | grep -qE '^kea '"

echo "--- info.<domain>/certs/: CA certificates for every system (1.5.1.5); web UI at fabric.<domain>"
docker cp "$REPO/tests/sandbox/certs_page_test.sh" "$NAME:/root/certs_page_test.sh"
in_box 'bash /root/certs_page_test.sh info.lan.test ca.lan.test $(python3 -c "import yaml;print(yaml.safe_load(open(\"/opt/fabric/config/vars.yaml\"))[\"ip_nginx\"])") '"$IP" \
    > "$OUT/certs-page.log" 2>&1
check "certs page at info.<domain>/certs/: every format real, right CA, right MIME, plain HTTP by name and IP, the CRLs; ca.<domain> stays Step-CA; certs.<domain> gone" \
    "! grep -q '^FAIL' '$OUT/certs-page.log' && [ \"\$(grep -c '^PASS' '$OUT/certs-page.log')\" -ge 25 ]"
check "DNS: info.<domain> and fabric.<domain> resolve to the host" \
    "in_box 'dig +short @$IP info.lan.test' | grep -qx $IP && in_box 'dig +short @$IP fabric.lan.test' | grep -qx $IP"
check "negative: certs.<domain> no longer resolves (1.5.1.5)" \
    "[ -z \"\$(in_box 'dig +short @$IP certs.lan.test')\" ]"
check "web UI answers at fabric.<domain> (refuses without a client cert)" \
    "[ \"\$(in_box 'curl -s -o /dev/null -w %{http_code} --cacert /opt/stepca/data/certs/root_ca.crt --resolve fabric.lan.test:443:$IP https://fabric.lan.test/')\" = 400 ]"

check "the root CA allows one level of nesting (ca_nest_depth 1: path length 2); its intermediate signs leaves only" \
    "in_box 'openssl x509 -in /opt/stepca/data/certs/root_ca.crt -noout -ext basicConstraints' | grep -q 'pathlen:2' && in_box 'openssl x509 -in /opt/stepca/data/certs/intermediate_ca.crt -noout -ext basicConstraints' | grep -q 'pathlen:0'"
echo "--- federation endpoint: enable, invite, refuse a bad join, revoke, disable"
FED_CURL="curl -s --cacert /opt/stepca/data/certs/root_ca.crt --resolve federation.lan.test:443:$IP"
in_box 'fabricctl federation enable' > "$OUT/fed-enable.log" 2>&1
check "federation: enable issues the endpoint's certificate and applies" \
    "grep -q 'federation endpoint on: https://federation.lan.test' '$OUT/fed-enable.log' && in_box 'test -s /opt/nginx/certs/federation.lan.test/fullchain.pem'"
check "federation: fabric-federation runs; its socket is root:nginx 0660 in a 0750 directory" \
    "in_box 'systemctl is-active fabric-federation' | grep -qx active && [ \"\$(in_box 'stat -c %a:%U /opt/federation/run/federation.sock /opt/federation/run' | tr '\n' ' ')\" = '660:root 750:root ' ]"
check "federation: federation.<domain> resolves and answers health over CA-verified TLS through nginx" \
    "in_box 'dig +short @$IP federation.lan.test' | grep -qx $IP && in_box '$FED_CURL https://federation.lan.test/v1/health' | grep -q '\"ok\": true'"
check "federation: only the federation routes are served there" \
    "[ \"\$(in_box '$FED_CURL -o /dev/null -w %{http_code} https://federation.lan.test/v1/secrets')\" = 404 ]"
INVITE=$(in_box 'fabricctl federation invite branch1' | grep -o 'fabric-join-1\.[A-Za-z0-9_-]*' | head -1)
check "federation: invite prints a one-time invitation; status lists it" \
    "[ -n '$INVITE' ] && in_box 'fabricctl federation status' | grep -q 'invitation .* for branch1'"
printf '%s' '{"id":"000000000000","secret":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","site":"branch1","csr":"x","domain":"branch1.lan.test","address":"10.9.9.9"}' > "$OUT/badjoin.json"
docker cp "$OUT/badjoin.json" "$NAME:/root/badjoin.json"
check "federation: a join with a wrong secret is refused through nginx (400, no reason given)"     "in_box '$FED_CURL -w \" %{http_code}\" -H Content-Type:application/json --data @/root/badjoin.json https://federation.lan.test/v1/join' | grep -q 'not valid.* 400$'"
check "federation: the invitation's secret is in neither vars nor the audit log" \
    "secret=\$(python3 -c \"import base64,json,sys;t='$INVITE'.split('.',1)[1];print(json.loads(base64.urlsafe_b64decode(t+'==='))['secret'])\") && [ -n \"\$secret\" ] && ! in_box \"grep -rqF \$secret /opt/fabric/config /opt/fabric/archive\""
check "federation: revoke withdraws it" "in_box 'fabricctl federation revoke branch1' | grep -q 'withdrawn: 1' && in_box 'fabricctl federation invitations' | grep -q 'no open invitations'"
check "federation: doctor passes with the endpoint on" "in_box 'fabricctl doctor' 2>&1 | grep -q 'federation endpoint, TLS verified' && ! in_box 'fabricctl doctor' 2>&1 | grep -q '✗'"
in_box 'fabricctl federation disable' > "$OUT/fed-disable.log" 2>&1
check "federation: disable removes the unit, its socket and the vhost" \
    "grep -q 'federation endpoint off' '$OUT/fed-disable.log' && ! in_box 'test -e /etc/systemd/system/fabric-federation.service' && ! in_box 'test -e /opt/federation' && ! in_box 'grep -q federation.lan.test /opt/nginx/config/nginx.conf'"

echo "--- systemd control: fabric.target"
check "fabric.target enabled and active" "in_box 'systemctl is-enabled fabric.target && systemctl is-active fabric.target' >/dev/null"
check "every unit is part of fabric.target" \
    "[ \"\$(in_box 'systemctl list-dependencies --plain fabric.target' | grep -cE '(bind9|stepca|nginx|samba|postgres|keycloak|fabric-agent|fabric-web)\\.service')\" -ge 8 ]"
in_box 'fabricctl status' > "$OUT/status.log" 2>&1
check "fabricctl status: target active, containers healthy" \
    "grep -qE '^fabric.target +active' '$OUT/status.log' && [ \"\$(grep -c ' healthy' '$OUT/status.log')\" -ge 7 ]"
in_box 'fabricctl stop' > "$OUT/stop.log" 2>&1
check "fabricctl stop: every service stopped" \
    "! in_box 'systemctl is-active bind9 stepca nginx samba postgres keycloak openbao fabric-web fabric-agent' | grep -qx active"
check "fabricctl stop: DNS no longer answers" "! in_box 'dig +time=2 +tries=1 +short @$IP ns.lan.test' | grep -qx $IP"
check "fabricctl stop: the host keeps its time (chrony is not part of the stack)" \
    "in_box 'systemctl is-active chrony' | grep -qx active"
in_box 'fabricctl start' > "$OUT/start.log" 2>&1
sleep 20
in_box 'fabricctl doctor' > "$OUT/doctor-after-start.log" 2>&1
check "fabricctl start: everything back, doctor passes" \
    "! grep -q '✗' '$OUT/doctor-after-start.log' && grep -q '✓' '$OUT/doctor-after-start.log'"
in_box 'systemctl restart fabric.target' > /dev/null 2>&1
sleep 20
in_box 'fabricctl doctor' > "$OUT/doctor-after-restart.log" 2>&1
check "systemctl restart fabric.target: doctor passes" \
    "! grep -q '✗' '$OUT/doctor-after-restart.log' && grep -q '✓' '$OUT/doctor-after-restart.log'"

cat > "$OUT/secrets_dump.py" <<'PY'
import json, sys
sys.path.insert(0, "/opt/fabric/lib")
from fabriclib.secrets.load_secrets import load_secrets
print(json.dumps(load_secrets("/opt/fabric/config/fabric-secrets.yml")))
PY
docker cp "$OUT/secrets_dump.py" "$NAME:/root/secrets_dump.py"
secrets_json() { in_box 'python3 /root/secrets_dump.py'; }

echo "--- fabric's secrets live in OpenBao, not on disk"
check "no plaintext fabric-secrets.yml after setup" "! in_box 'test -e /opt/fabric/config/fabric-secrets.yml'"
check "the marker says OpenBao is the source of truth" "in_box 'test -s /opt/fabric/config/secrets.openbao'"
check "fabricctl vault status: secrets in OpenBao (fabric/secrets)" "in_box 'fabricctl vault status' | grep -q \"fabric's secrets: in OpenBao (fabric/secrets\""
check "every generated secret is in OpenBao" \
    "secrets_json | python3 -c 'import json,sys; s=json.load(sys.stdin); sys.exit(0 if all(s.get(k) for k in (\"ca_password\",\"rndc_secret\",\"ad_admin_password\",\"keycloak_admin_password\",\"webui_oidc_secret\",\"ad_agent_password\")) else 1)'"

check "fabricctl secrets list: names only, no values" \
    "in_box 'fabricctl secrets list' | grep -qx keycloak_admin_password && ! in_box 'fabricctl secrets list' | grep -qF \"\$(secrets_json | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"keycloak_admin_password\"])')\""
check "fabricctl secrets show: the value, and the read is audited" \
    "[ \"\$(in_box 'fabricctl secrets show tsig/npm')\" = '$TSIG_SECRET' ] && in_box 'grep -q \"SECRET_READ | name=tsig/npm\" /opt/fabric/archive/audit.log'"

echo "--- RFC2136 with the embedded TSIG key (what nginx-proxy-manager does)"
docker cp "$REPO/tests/sandbox/rfc2136_test.sh" "$NAME:/root/rfc2136_test.sh"
rfc2136() { in_box "bash /root/rfc2136_test.sh $IP lan.test npm '$TSIG_SECRET' npm $BIND_PORT" 2>&1 | tee -a "$OUT/rfc2136.log"; }
rfc2136 > /dev/null
check "RFC2136: embedded key updates _acme-challenge.npm, other names and wrong keys refused" \
    "grep -q '4 passed, 0 failed' '$OUT/rfc2136.log'"
check "embedded secret kept exactly (in OpenBao), never in vars or fabric.yaml" \
    "secrets_json | grep -qF '$TSIG_SECRET' && in_box \"! grep -qF '$TSIG_SECRET' /opt/fabric/config/vars.yaml /opt/fabric/config/fabric.yaml\""
check "rfc2136.ini for the key: host IP, BIND's port ($BIND_PORT, behind the DNS filter), 0600" \
    "in_box \"grep -qx 'dns_rfc2136_server = $IP' /opt/npm/rfc2136.ini && grep -qx 'dns_rfc2136_port = $BIND_PORT' /opt/npm/rfc2136.ini && [ \\\$(stat -c %a /opt/npm/rfc2136.ini) = 600 ]\""

echo "--- admin login kit"
check "kit: .p12, its password and root CA in ~/fabric-admin; no sign-in password written there (2.1.6.33)" \
    "in_box 'cd /root/fabric-admin && ls fabric-admin.p12 p12-password.txt README.txt *.crt' >/dev/null \
     && ! in_box 'test -e /root/fabric-admin/initial-password.txt'"
check "kit: secrets are 0600" \
    "[ \"\$(in_box 'stat -c %a /root/fabric-admin/fabric-admin.p12 /root/fabric-admin/p12-password.txt' | sort -u)\" = 600 ]"

echo "--- OpenBao (core): static-seal auto-unseal, recovery keys once, AppRoles, TLS via nginx"
check "fabricctl vault status: unsealed, static seal, raft" "in_box 'fabricctl vault status' | grep -q 'unsealed  (static seal, raft storage)'"
check "recovery key written once into ~/fabric-admin, 0600" \
    "[ \"\$(in_box 'stat -c %a /root/fabric-admin/openbao-recovery-keys.txt')\" = 600 ]"
check "vault key in the key-file unlock method: root 0400; store root 0600"     "[ \"\$(in_box 'stat -c %a:%U /etc/fabric/openbao/local-fabric-1.key /etc/fabric/openbao/slots.json' | tr '\n' ' ')\" = '400:root 600:root ' ]"
check "no vault key left in RAM once OpenBao is unsealed" "! in_box 'ls /run/fabric/openbao/*.key' >/dev/null 2>&1"
check "fabricctl vault slots lists the key-file method, present" "in_box 'fabricctl vault slots' | grep -qE '^● local +local +fabric-1'"
check "fabricctl vault test local: unwraps and verifies the vault key" "in_box 'fabricctl vault test local' | grep -q 'check value matches'"
check "the initial root token is revoked and not kept on disk" "! in_box 'test -e /etc/fabric/openbao/bootstrap-root-token'"
check "AppRole credentials: root-only 0400" \
    "[ \"\$(in_box 'stat -c %a:%U /etc/fabric/openbao/setup-approle.json /etc/fabric/openbao/agent-approle.json' | sort -u)\" = 400:root ]"
check "https://vault.lan.test through nginx, TLS verified against the fabric CA" \
    "in_box 'curl -s --cacert /opt/stepca/data/certs/root_ca.crt --resolve vault.lan.test:443:$IP https://vault.lan.test/v1/sys/health' | grep -q '\"sealed\":false'"
in_box 'systemctl restart openbao' > /dev/null 2>&1; sleep 10
check "OpenBao unseals itself after a restart (fabric-unlock, nobody enters a key)" "in_box 'fabricctl vault status' > /dev/null"
check "...and the key was wiped from RAM again" "! in_box 'ls /run/fabric/openbao/*.key' >/dev/null 2>&1"
in_box 'fabricctl vault rotate --yes' > "$OUT/rotate.log" 2>&1
check "fabricctl vault rotate: new key fabric-2, OpenBao unsealed, fabric's secrets still readable"     "grep -q 'rotated to fabric-2' '$OUT/rotate.log' && in_box 'fabricctl vault status' > /dev/null && in_box 'fabricctl secrets list' | grep -qx ca_password"
check "rotation shredded the old key file" "! in_box 'test -e /etc/fabric/openbao/local-fabric-1.key' && in_box 'test -e /etc/fabric/openbao/local-fabric-2.key'"
in_box 'systemctl stop openbao; systemctl restart bind9 nginx' > /dev/null 2>&1; sleep 10
check "core services start and serve while OpenBao is down" \
    "in_box 'dig +short @$IP ns.lan.test' | grep -qx $IP && ! in_box 'systemctl is-active --quiet openbao'"
in_box 'systemctl start openbao' > /dev/null 2>&1; sleep 10

echo "--- restricted sign-in: HTTPS + client cert from this CA + Keycloak OIDC/TOTP + the console's admin role"
# A person of the site who is NOT in admins (bob), and one in auditors (carol), each with a client certificate;
# their one-time passwords from fabric's own reset, through a root-only file
docker cp "$REPO/tests/sandbox/make_person.py" "$NAME:/root/make_person.py"
docker cp "$REPO/tests/host/reset_user.py" "$NAME:/root/reset_user.py"
in_box 'python3 /root/make_person.py bob' > "$OUT/bob.log" 2>&1
in_box 'python3 /root/reset_user.py bob /root/bob-pw' >> "$OUT/bob.log" 2>&1
BOB_PW=$(in_box 'cat /root/bob-pw; rm -f /root/bob-pw')
BOB_P12_PW=$(in_box 'fabricctl client-cert bob' 2>&1 | sed -n 's/^.p12 password (shown once): //p')
check "second user bob (a person of the site, not an admin) with a client cert" "grep -q created '$OUT/bob.log' && [ -n '$BOB_P12_PW' ]"
in_box 'python3 /root/make_person.py carol auditors' > "$OUT/carol.log" 2>&1
in_box 'python3 /root/reset_user.py carol /root/carol-pw' >> "$OUT/carol.log" 2>&1
CAROL_PW=$(in_box 'cat /root/carol-pw; rm -f /root/carol-pw')
CAROL_P12_PW=$(in_box 'fabricctl client-cert carol' 2>&1 | sed -n 's/^.p12 password (shown once): //p')
check "third user carol in the auditors group, with a client cert" "grep -q created '$OUT/carol.log' && [ -n '$CAROL_P12_PW' ]"
BOB_UID=$(in_box "docker exec samba ldbsearch -H /data/private/sam.ldb '(sAMAccountName=bob)' uidNumber" | grep ^uidNumber)
CAROL_UID=$(in_box "docker exec samba ldbsearch -H /data/private/sam.ldb '(sAMAccountName=carol)' uidNumber" | grep ^uidNumber)
check "bob and carol have distinct uid numbers from the site's block" "[ -n '$BOB_UID' ] && [ '$BOB_UID' != '$CAROL_UID' ]"
echo "--- Keycloak's database password, rotated by OpenBao (2.1.7.4)"
pg_roles() { in_box "docker exec postgres psql -tA -U fabric_admin -d keycloak -c 'SELECT rolname, rolsuper, rolcanlogin FROM pg_roles'"; }
check "setup handed Keycloak's password to OpenBao: Keycloak runs as its own role, the bootstrap role locked" \
    "pg_roles | grep -qx 'keycloak_db|f|t' && pg_roles | grep -qx 'keycloak|t|f' && pg_roles | grep -qx 'fabric_admin|t|t'"
in_box 'fabricctl vault rotate-db' > "$OUT/rotate-db.log" 2>&1
check "fabricctl vault rotate-db: rotated, Keycloak restarted with it and healthy; doctor's rotation check passes"     "grep -q 'Keycloak restarted with it and healthy' '$OUT/rotate-db.log' && in_box 'fabricctl doctor' | grep -q 'rotated by OpenBao in the last 40 days'"
check "the monthly fabric-db-rotate timer is on" "in_box 'systemctl is-enabled fabric-db-rotate.timer' | grep -qx enabled"
docker cp "$REPO/tests/sandbox/login_test.py" "$NAME:/root/login_test.py"
in_box "FABRIC_ADMIN_PW='$ADMIN_PW' CAROL_PW='$CAROL_PW' CAROL_P12_PW='$CAROL_P12_PW' python3 /root/login_test.py /opt/fabric/config/vars.yaml bob '$BOB_PW' '$BOB_P12_PW'" 2>&1 | tee "$OUT/login.log"
in_box 'journalctl --no-pager CONTAINER_NAME=nginx | grep -iE "oidc|error" | tail -40'     > "$OUT/login-nginx.log" 2>&1     # diagnosis when a sign-in check fails
cat > "$OUT/reset_guard.py" <<'PY'
import sys, yaml
sys.path.insert(0, "/opt/fabric/lib")
from fabriclib.common.errors import ValidationError
from fabriclib.directory.reset_sign_in import reset_sign_in
v = yaml.safe_load(open("/opt/fabric/config/vars.yaml"))
try:
    reset_sign_in(v, "helpdesk-test", "carol", privileged=False, source="test")
    print("RESET ALLOWED")
except ValidationError as e:
    print(e)
PY
docker cp "$OUT/reset_guard.py" "$NAME:/root/reset_guard.py"
check "people: without the admin bundle, a fabric-group member's sign-in cannot be reset (carol, auditors)" \
    "in_box 'python3 /root/reset_guard.py' | grep -q 'only an admin can reset'"
check "sign-in: admin gets in; HTTP, missing/foreign certs, non-admins and borrowed certs are refused" \
    "! grep -q '^FAIL' '$OUT/login.log' && [ \"\$(grep -c '^PASS' '$OUT/login.log')\" -ge 11 ]"

echo "--- container images: pinned, status, update (compose down/up, health-gated)"
NGX_OLD=sha256:d5792f71a9496b833bc08ea834a758c46e2b6a6306c10f4be926f38a656cdc1c     # nginx 1.30.4
NGX_REF="nginx:1.30.4@$NGX_OLD"
docker cp "$REPO/tests/sandbox/set_lock.py" "$NAME:/root/set_lock.py"
certs_ok() { [ "$(in_box "curl -s -o /dev/null -w %{http_code} http://$IP/certs/")" = 200 ]; }
nginx_ref() { in_box 'docker inspect -f {{.Config.Image}} nginx'; }
check "every running image is pinned by digest; images status: all current" \
    "! in_box 'docker inspect -f {{.Config.Image}} \$(docker ps -q)' | grep -vE '@sha256:|^fabric/' && in_box 'fabricctl images status' | grep -q 'all images current'"
in_box "python3 /root/set_lock.py nginx nginx 1.30.4 $NGX_OLD"
check "a new validated list only reports: status shows the nginx update, nothing changed" \
    "in_box 'fabricctl images status' | grep -qE '^nginx +update available' && [ \"\$(nginx_ref)\" != '$NGX_REF' ]"
in_box 'fabricctl images update nginx' > "$OUT/images-update.log" 2>&1
check "images update nginx: recreated on the validated image, healthy, serving; others untouched" \
    "grep -q 'updated nginx' '$OUT/images-update.log' && [ \"\$(nginx_ref)\" = '$NGX_REF' ] && certs_ok && in_box 'fabricctl images status' | grep -qE '^keycloak +current'"

echo "--- setup again (must converge without changes)"
in_box 'fabricctl setup --non-interactive --yes' 2>&1 | tee "$OUT/setup2.log"
check "re-run completes" "grep -q 'fabric is ready' '$OUT/setup2.log'"
check "re-run re-issues no certificates" "! grep -q ': issued' '$OUT/setup2.log'"
check "re-run neither re-initialises nor changes OpenBao" \
    "! grep -q 'OpenBao initialised' '$OUT/setup2.log' && grep -q 'OpenBao configured (no changes)' '$OUT/setup2.log'"
check "re-run keeps the admin and their certificate" \
    "grep -q \"admin 'fabric-admin' exists\" '$OUT/setup2.log' && grep -q 'is current' '$OUT/setup2.log'"
check "re-run keeps the images this host runs (a fabric upgrade never changes them)" \
    "[ \"\$(nginx_ref)\" = '$NGX_REF' ]"
in_box 'fabricctl images rollback nginx' > "$OUT/images-rollback.log" 2>&1
check "images rollback nginx: back to the image before the update" \
    "grep -q 'rolled back nginx' '$OUT/images-rollback.log' && [ \"\$(nginx_ref)\" != '$NGX_REF' ] && certs_ok"
in_box "python3 /root/set_lock.py nginx busybox 1.37 sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
in_box 'fabricctl images update nginx' > "$OUT/images-bad.log" 2>&1
in_box 'journalctl -u nginx --no-pager -n 120' > "$OUT/images-bad-journal.log" 2>&1    # kept for an intermittent failure
check "a validated image that does not come up healthy is rolled back by itself" \
    "grep -q 'rolled back to' '$OUT/images-bad.log' && nginx_ref | grep -q '^nginx:1.30.5@' && certs_ok"
in_box "python3 /root/set_lock.py nginx nginx 1.30.5 sha256:b972f831f200b19ef0767938224f9711e74cd783718738cd7405d5cabf75c442"
in_box 'fabricctl images prune' > "$OUT/images-prune.log" 2>&1
check "images prune keeps the rollback image and everything in use" \
    "in_box 'docker image inspect nginx@$NGX_OLD' >/dev/null 2>&1 && in_box 'fabricctl images status' | grep -q 'all images current'"

docker cp "$REPO/tests/sandbox/agent_job.py" "$NAME:/root/agent_job.py"
in_box 'python3 /root/agent_job.py doctor' > "$OUT/doctor-job.json" 2>&1
check "doctor as an agent job (the web console's Run doctor): done, every check passed"     "python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); sys.exit(not (j[\"state\"] == \"done\" and j[\"result\"][\"failed\"] == 0 and j[\"result\"][\"checks\"]))' '$OUT/doctor-job.json'"
in_box 'python3 /root/agent_job.py images update nginx' > "$OUT/images-job.json" 2>&1
check "an image update as an agent job (the web console's Updates): done, nothing to move while current"     "grep -q '\"state\": \"done\"' '$OUT/images-job.json' && grep -q 'nothing to update' '$OUT/images-job.json'"

echo "--- setup with a changed setting (live DNS zone must update, bind9 keeps serving)"
cat > "$OUT/change.yaml" <<EOF
dns:
  dynamic_zone_var:
    zone_authority: true
    A:
    - { name: rerun-test, ip: 10.77.0.99 }
EOF
docker cp "$OUT/change.yaml" "$NAME:/root/change.yaml"
# an install from before pinning had floating refs and the old web image name in its vars
in_box "python3 -c \"import yaml; p='/opt/fabric/config/vars.yaml'; v=yaml.safe_load(open(p)); v.update(image_nginx='nginx:latest', image_bind9='ubuntu/bind9:latest', image_webui='fabric/webui:local'); yaml.safe_dump(v, open(p, 'w'))\""
in_box 'fabricctl setup --file /root/change.yaml --non-interactive --yes' > "$OUT/setup3.log" 2>&1
check "re-run with a change completes" "grep -q 'fabric is ready' '$OUT/setup3.log'"
check "upgrade: floating image refs and old names replaced by the validated pins" \
    "in_box 'grep -E \"^image_(nginx|bind9|webui):\" /opt/fabric/config/vars.yaml' | tr '\n' ' ' | grep -q 'image_nginx: nginx:1.30.5@sha256:.*image_webui: fabric/web:local' && ! in_box 'grep -q ^image_bind9: /opt/fabric/config/vars.yaml'"
check "new record served by the running bind9" \
    "in_box 'dig +short @$IP rerun-test.lan.test' | grep -qx 10.77.0.99"
if ! in_box "dig +short @$IP rerun-test.lan.test" | grep -qx 10.77.0.99; then
    echo "    diag: zone files: $(in_box 'grep -rl rerun-test /opt/bind9 2>/dev/null' | xargs)"
    echo "    diag: SOA served: $(in_box "dig +short SOA @$IP lan.test")"
    in_box 'docker logs --tail 20 bind9 2>&1' | sed 's/^/    diag: bind9: /'
fi
: > "$OUT/rfc2136.log"; rfc2136 > /dev/null
check "RFC2136 key still works after the re-runs (secret unchanged)" "grep -q '4 passed, 0 failed' '$OUT/rfc2136.log'"

echo "--- fabricctl tsig / acl on the running install"
ACLF=/opt/bind9/config/named.conf.acl
t2136() { in_box "bash /root/rfc2136_test.sh $IP lan.test $1 '$2' $3 $BIND_PORT" 2>&1 | tail -1; }   # key secret host
secret_of() { secrets_json | python3 -c "import json,sys; print(json.load(sys.stdin)['tsig_secrets']['$1'])"; }
check "vars file: npm key is in ACL npm-updaters" \
    "in_box \"sed -n '/acl \\\"npm-updaters\\\"/,/};/p' $ACLF\" | grep -q 'key \"npm\"'"

S2=$(openssl rand -base64 32)
in_box "umask 077; printf '%s' '$S2' > /root/nas.secret"
in_box 'fabricctl tsig add nas --record nas --secret-file /root/nas.secret --acl nas-updaters' > "$OUT/tsig.log" 2>&1
check "tsig add: existing secret kept, key in ACL nas-updaters" \
    "grep -q \"TSIG key 'nas' added (existing secret kept), in ACL nas-updaters.\" '$OUT/tsig.log'"
check "tsig add: key works over RFC2136" "[ \"\$(t2136 nas '$S2' nas)\" = '4 passed, 0 failed' ]"
check "tsig add: ACL rendered with the key" "in_box \"sed -n '/acl \\\"nas-updaters\\\"/,/};/p' $ACLF\" | grep -q 'key \"nas\"'"

in_box 'fabricctl tsig rotate nas' >> "$OUT/tsig.log" 2>&1
S3=$(secret_of nas)
check "tsig rotate: old secret refused" "[ \"\$(t2136 nas '$S2' nas | cut -d' ' -f1)\" != 4 ]"
check "tsig rotate: new secret works" "[ -n '$S3' ] && [ '$S3' != '$S2' ] && [ \"\$(t2136 nas '$S3' nas)\" = '4 passed, 0 failed' ]"
check "tsig rotate: rfc2136.ini carries the new secret" "in_box \"grep -qxF 'dns_rfc2136_secret = $S3' /opt/nas/rfc2136.ini\""

in_box 'fabricctl tsig set-secret nas --secret-file /root/nas.secret' >> "$OUT/tsig.log" 2>&1
check "tsig set-secret: the given secret works again" "[ \"\$(t2136 nas '$S2' nas)\" = '4 passed, 0 failed' ]"

in_box 'fabricctl tsig update nas --record web' >> "$OUT/tsig.log" 2>&1
check "tsig update: new record allowed" "[ \"\$(t2136 nas '$S2' web)\" = '4 passed, 0 failed' ]"
check "tsig update: old record no longer allowed" "[ \"\$(t2136 nas '$S2' nas | cut -d' ' -f1)\" != 4 ]"

in_box "fabricctl acl add lab 192.168.50.0/24 10.9.9.9 'key nas'" >> "$OUT/tsig.log" 2>&1
check "acl add: rendered with CIDR, IP and key" \
    "in_box \"sed -n '/acl \\\"lab\\\"/,/};/p' $ACLF\" | tr -d ' ' | grep -c -e '192.168.50.0/24;' -e '10.9.9.9;' -e 'key\"nas\";' | grep -qx 3"
check "acl add: rejects nonsense" "! in_box \"fabricctl acl add lab 'not-an-ip'\" >/dev/null 2>&1"
check "acl remove: built-in ACL protected" "! in_box 'fabricctl acl remove dns-resolvers' >/dev/null 2>&1"
in_box 'fabricctl acl remove lab 10.9.9.9' >> "$OUT/tsig.log" 2>&1
check "acl remove: one entry" "! in_box \"grep -q '10.9.9.9' $ACLF\""

echo "--- ACL policy: only certbot devices in the ACL may prove names for certificates"
D1=$(openssl rand -base64 32); D2=$(openssl rand -base64 32)
in_box "umask 077; printf '%s' '$D1' > /root/d1.secret; printf '%s' '$D2' > /root/d2.secret"
in_box 'fabricctl acl policy certbot-devices --record web' >> "$OUT/tsig.log" 2>&1
in_box 'fabricctl tsig add dev1 --acl certbot-devices --secret-file /root/d1.secret' >> "$OUT/tsig.log" 2>&1
in_box 'fabricctl tsig add dev2 --secret-file /root/d2.secret' >> "$OUT/tsig.log" 2>&1
check "policy: device key in the ACL may set _acme-challenge.web (other names refused)" \
    "[ \"\$(t2136 dev1 '$D1' web)\" = '4 passed, 0 failed' ]"
check "policy: a key outside the ACL has no update rights (deny by default)" \
    "[ \"\$(t2136 dev2 '$D2' web | cut -d' ' -f1)\" != 4 ]"
check "policy: tsig list shows rights via the ACL and none for the other key" \
    "in_box 'fabricctl tsig list' | grep -A1 '^dev1' | grep -q 'via ACL certbot-devices' && in_box 'fabricctl tsig list' | grep '^dev2' | grep -q 'no update rights'"
in_box 'fabricctl acl policy certbot-devices --record web --record git' >> "$OUT/tsig.log" 2>&1
check "policy: widened to git, members follow" "[ \"\$(t2136 dev1 '$D1' git)\" = '4 passed, 0 failed' ]"
in_box 'fabricctl tsig update dev1 --drop-acl certbot-devices' >> "$OUT/tsig.log" 2>&1
check "policy: key taken out of the ACL loses the rights" "[ \"\$(t2136 dev1 '$D1' web | cut -d' ' -f1)\" != 4 ]"
in_box 'fabricctl tsig update dev1 --acl certbot-devices' >> "$OUT/tsig.log" 2>&1
in_box 'fabricctl acl policy certbot-devices --clear' >> "$OUT/tsig.log" 2>&1
check "policy cleared: members lose the rights" "[ \"\$(t2136 dev1 '$D1' web | cut -d' ' -f1)\" != 4 ]"
in_box 'fabricctl tsig remove dev1 && fabricctl tsig remove dev2 && fabricctl acl remove certbot-devices' >> "$OUT/tsig.log" 2>&1
check "policy: cleanup leaves no trace in BIND's config" \
    "! in_box \"grep -rqE 'dev1|dev2|certbot-devices' /opt/bind9/config\""

in_box 'fabricctl tsig remove nas' >> "$OUT/tsig.log" 2>&1
in_box "bash /root/rfc2136_test.sh $IP lan.test nas '$S2' web $BIND_PORT" > "$OUT/tsig-removed.log" 2>&1
check "tsig remove: key refused by BIND" "grep -q '^FAIL RFC2136 update with the embedded key accepted' '$OUT/tsig-removed.log'"
check "tsig remove: key gone from every ACL" "! in_box \"grep -q 'key \\\"nas\\\"' $ACLF\""
check "tsig remove: rfc2136.ini deleted" "! in_box 'test -e /opt/nas/rfc2136.ini'"
check "BIND still serves after all changes" "in_box 'dig +short @$IP ns.lan.test' | grep -qx $IP"
check "the npm key is unaffected" "[ \"\$(t2136 npm '$TSIG_SECRET' npm)\" = '4 passed, 0 failed' ]"

echo "--- package upgrade and removal"
sleep 2    # a later build timestamp = a newer package version
DEB2=$(OUT="$OUT/dist2" bash "$REPO/packaging/deb/build-deb.sh")
docker cp "$DEB2" "$NAME:/root/fabricctl-new.deb"
in_box 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /root/fabricctl-new.deb' > "$OUT/apt2.log" 2>&1
check "newer package installs over the old one" "grep -q 'package updated' '$OUT/apt2.log'"
check "until setup runs, commands say the package is newer" "in_box 'fabricctl status' 2>&1 | grep -q 'package is newer'"
# what builds before 0.6.4 left beside the package's copy: one line the install has, one it lacks
in_box 'mkdir -p /usr/lib/fabricctl/fabric/archive && tail -1 /opt/fabric/archive/audit.log > /usr/lib/fabricctl/fabric/archive/audit.log \
        && echo "[stray] an earlier build wrote this" >> /usr/lib/fabricctl/fabric/archive/audit.log'
in_box 'fabricctl setup --non-interactive --yes' > "$OUT/setup-upgrade.log" 2>&1
check "setup applies the upgrade" "grep -q 'fabric is ready' '$OUT/setup-upgrade.log' && ! in_box 'fabricctl status' 2>&1 | grep -q 'package is newer'"
check "the install runs the upgraded build" "in_box 'cmp /usr/lib/fabricctl/fabric/BUILD /opt/fabric/BUILD'"
check "records an earlier build left beside the package's copy adopted once, the stray folder gone" \
    "[ \"\$(in_box 'grep -cF \"[stray] an earlier build\" /opt/fabric/archive/audit.log')\" = 1 ] \
     && ! in_box 'test -e /usr/lib/fabricctl/fabric/archive'"
in_box 'DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq fabricctl' > "$OUT/apt-remove.log" 2>&1
check "apt remove removes the command but not the running install" \
    "! in_box 'test -e /usr/bin/fabricctl' && in_box 'systemctl is-active fabric.target' | grep -qx active && in_box 'dig +short @$IP ns.lan.test' | grep -qx $IP"
in_box 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /root/fabricctl-new.deb' > /dev/null 2>&1
check "reinstalling the package gives the command back" "in_box 'fabricctl status' | grep -qE '^fabric.target +active'"

echo "--- reinstall keeps fabric's secrets (backup exports them, setup re-imports and shreds) and the domain"
in_box 'python3 /root/make_person.py keeper' > "$OUT/keeper.log" 2>&1
SID_BEFORE=$(in_box "docker exec samba ldbsearch -H /data/private/sam.ldb '(sAMAccountName=keeper)' objectSid" | sed -n 's/^objectSid: //p')
in_box 'fabricctl reinstall --yes --non-interactive' > "$OUT/reinstall.log" 2>&1
check "reinstall completes" "grep -q 'fabric is ready' '$OUT/reinstall.log'"
check "reinstall re-imported the exported secrets into OpenBao and left no plaintext file" \
    "grep -q 'restored secrets file matched OpenBao; shredded' '$OUT/reinstall.log' && ! in_box 'test -e /opt/fabric/config/fabric-secrets.yml'"
check "after the reinstall the npm TSIG key still works" "[ \"\$(t2136 npm '$TSIG_SECRET' npm)\" = '4 passed, 0 failed' ]"
in_box 'fabricctl doctor' > "$OUT/doctor-reinstall.log" 2>&1
check "after the reinstall doctor passes" "! grep -q '✗' '$OUT/doctor-reinstall.log' && grep -q '✓' '$OUT/doctor-reinstall.log'"
check "the domain survives the reinstall: a person made before it is still there, with the same SID (not a new domain)"     "[ -n '$SID_BEFORE' ] && in_box \"docker exec samba ldbsearch -H /data/private/sam.ldb '(sAMAccountName=keeper)' objectSid\" | grep -q 'objectSid: $SID_BEFORE'"

cat > "$OUT/argv_check.py" <<'PY'
import glob, sys
sys.path.insert(0, "/opt/fabric/lib")
from fabriclib.secrets.load_secrets import load_secrets
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
docker cp "$OUT/argv_check.py" "$NAME:/root/argv_check.py"
check "no secret appears in any process's argv" "in_box 'python3 /root/argv_check.py' | grep -q 'LEAKS: none'"

echo "--- fabricctl uninstall: export to a folder of your choice, remove fabric and the package"
CA_FP=$(in_box 'openssl x509 -noout -fingerprint -sha256 -in /opt/stepca/data/certs/root_ca.crt')
# a person made after the reinstall (which starts the domain fresh): only the export has her
in_box 'python3 /root/make_person.py erin' > "$OUT/erin.log" 2>&1
in_box 'fabricctl uninstall --yes' > "$OUT/uninstall-refused.log" 2>&1
check "unattended uninstall without an export choice is refused, nothing changed"     "grep -q 'choose --export DIR or --no-export' '$OUT/uninstall-refused.log' && in_box 'systemctl is-active fabric.target' | grep -qx active"
in_box 'fabricctl uninstall --yes --export /opt/fabric/exported' > "$OUT/uninstall-refused2.log" 2>&1
check "an export folder the uninstall would delete is refused"     "grep -q 'would be deleted by the uninstall' '$OUT/uninstall-refused2.log' && in_box 'systemctl is-active fabric.target' | grep -qx active"
in_box 'fabricctl uninstall --yes --export /root/fabric-export --purge-package' > "$OUT/uninstall.log" 2>&1
EX=/root/fabric-export
check "export: config, secrets, CA, directory, Keycloak, the vault and its key, README (root 0700)"     "in_box 'test -s $EX/fabric/config/fabric-secrets.yml && test -d $EX/stepca/data && test -d $EX/samba/data && test -d $EX/postgres && test -d $EX/openbao/data && test -f $EX/@root/etc/fabric/openbao/slots.json && test -f $EX/README.txt && [ \"\$(stat -c %a $EX)\" = 700 ]'"
check "the package was purged too, and nothing was written to /var/backups"     "! in_box 'dpkg -s fabricctl' >/dev/null 2>&1 && ! in_box 'test -e /var/backups/fabric'"
# the container names asked of Docker first, so a failing `docker ps` cannot pass for "none left"
LEFT_NAMES=$(in_box "docker ps -a --format '{{.Names}}'"); LEFT_RC=$?
check "no fabric container, network or unit is left"     "[ $LEFT_RC -eq 0 ] && ! grep -qxE 'bind9|bind9-resolver|step-ca|samba|keycloak|postgres|nginx|openbao|fabric-web|kea-dhcp4|kea-ddns|freeradius|fluentbit' <<<\"\$LEFT_NAMES\"      && ! in_box 'docker network inspect fabric_net' >/dev/null 2>&1      && ! in_box 'ls /etc/systemd/system/fabric.target /etc/systemd/system/{bind9,bind9-resolver,stepca,samba,keycloak,postgres,nginx,openbao,fabric-web,kea,freeradius,fabric-agent}.service' >/dev/null 2>&1"
check "no data, key, kill-switch rule, CA trust, command or service account is left"     "! in_box 'ls -d /opt/fabric /opt/bind9 /opt/stepca /opt/openbao /opt/dirsrv /opt/kea /opt/freeradius /etc/fabric/openbao /run/fabric/openbao /run/fabric/openbao-admin /etc/udev/rules.d/90-fabric-unlock.rules /usr/local/bin/fabricctl /usr/bin/fabricctl /etc/fabric /usr/lib/fabricctl' >/dev/null 2>&1      && ! in_box 'ls /usr/local/share/ca-certificates/fabric-*' >/dev/null 2>&1 && ! in_box 'id fabric-vault' >/dev/null 2>&1"
check "DNS is gone" "! in_box 'dig +time=2 +tries=1 +short @$IP ns.lan.test' | grep -qx $IP"
check "uninstall listed every host change first (removed, undone, kept)" \
    "grep -qE 'Secure this host +undone' '$OUT/uninstall.log' && grep -qE 'Ports fabric needs +undone' '$OUT/uninstall.log' && grep -qE 'Docker daemon settings +kept' '$OUT/uninstall.log' && grep -qE 'Service accounts +removed' '$OUT/uninstall.log'"
check "uninstall put chrony's own configuration back and left ufw as it was before fabric ($UFW_BEFORE)" \
    "! in_box 'grep -q \"^# fabric\" /etc/chrony/chrony.conf' && ! in_box 'ufw status' | grep -qE '22/tcp|123/udp' \
     && in_box 'ufw status' | grep -q \"Status: $UFW_BEFORE\""

echo "--- fabricctl restore: the same fabric back from the export"
in_box 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /root/fabricctl-new.deb' > "$OUT/apt-restore.log" 2>&1
in_box 'fabricctl restore /root/nope --yes' > "$OUT/restore-refused.log" 2>&1
check "restore refuses a folder that is not a fabric export" "grep -q 'is not a fabric export' '$OUT/restore-refused.log'"
in_box 'fabricctl restore /root/fabric-export --yes' > "$OUT/restore.log" 2>&1
check "restore: setup completes on the exported data" "grep -q 'fabric is ready' '$OUT/restore.log'"
check "restore: the same CA (clients keep trusting it)" \
    "[ \"\$(in_box 'openssl x509 -noout -fingerprint -sha256 -in /opt/stepca/data/certs/root_ca.crt')\" = '$CA_FP' ]"
check "restore: OpenBao unlocked with its own key, not re-initialised; fabric's secrets back in it" \
    "! grep -q 'OpenBao initialised' '$OUT/restore.log' && in_box 'fabricctl secrets list' | grep -q ca_password && ! in_box 'test -e /opt/fabric/config/fabric-secrets.yml'"
check "restore: the embedded TSIG key still updates DNS" "[ \"\$(t2136 npm '$TSIG_SECRET' npm)\" = '4 passed, 0 failed' ]"
check "restore: the domain is back (erin, added after the reinstall, exists again)" \
    "in_box \"docker exec samba ldbsearch -H /data/private/sam.ldb '(sAMAccountName=erin)' sAMAccountName\" | grep -qx 'sAMAccountName: erin'"
in_box 'fabricctl doctor' > "$OUT/doctor-restore.log" 2>&1
check "restore: doctor passes" "! grep -q '✗' '$OUT/doctor-restore.log' && grep -q '✓' '$OUT/doctor-restore.log'"

echo; echo "$PASS passed, $FAIL failed"
if [ "${KEEP:-0}" != 1 ]; then
    docker rm -f "$NAME" >/dev/null; docker network rm "$NET" >/dev/null; docker volume rm fabric-sbx-docker >/dev/null
fi
exit $FAIL
