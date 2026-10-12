#!/bin/bash
# Spike for the DNS filter's engine (manual 2.3.1.18), before the owner chooses. Throwaway (global Rule 4).
#   A. BIND in front, AdGuard Home behind it as the list matcher only, driven through its API (its query log,
#      statistics and web UI unused); fabric's zone answered by BIND, never reaching AdGuard; the owner's rules in
#      BIND; a group's view forwarding from its own address so AdGuard applies that group's rule; the block's marker
#      as dnstap records it; check_host naming the rule.
#   B. BIND alone, the same lists converted by fabric's converter and merged into one deduplicated zone.
# Both get the same downloaded copies of the owner's 15 lists (served from a local web server). Measured: memory,
# time to load, to add one more list (HaGeZi's Ultimate) and to toggle one, answer times for blocked and allowed
# names, a restart.
#     bash spikes/dns-engine/run.sh            (needs Docker and internet: the lists, Cloudflare)
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=${SPIKE_DIR:-$HOME/fabric-spike-dns}/engine
IDS=(1 2 59 30 71 54 8 18 9 11 53 51 55 56 44)   # the owner's 15 lists (AdGuard Home's page, 2026-10-11)
MORE=49                                           # HaGeZi's Ultimate: the one more to add
REG=https://adguardteam.github.io/HostlistsRegistry/assets
AG_IMAGE=${AG_IMAGE:-adguard/adguardhome@sha256:aba9e3bf0613be3ba3755e1fc311b126e2c24bec25e18b6483894a88283074f0}
BIND_IMAGE=fabric-spike/bind9-dnsfilter       # spikes/dns-filter's image: Debian 13's BIND 9.20
TOOLS=fabric-spike/dns-tools
A=172.30.54; B=172.30.55
FAILED=0
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; FAILED=$((FAILED + 1)); fi; }
mem() { docker stats --no-stream --format '{{.MemUsage}}' "$1" | cut -d/ -f1 | tr -d ' '; }
q() { docker exec "$1" dig +time=5 +tries=1 "@$2" "${@:3}"; }
# Purpose: seconds until a name answers with the given status through a server (polled every 0.2 s, up to 600 s).
wait_status() {
    local t0=$(date +%s.%N)
    for _ in $(seq 1 3000); do
        q sde-tools "$1" "$2" | grep -q "status: $3" && { echo "$(date +%s.%N) - $t0" | bc; return 0; }
        sleep 0.2
    done
    echo "never"; return 1
}
cleanup() {
    docker rm -f sde-web sde-auth sde-adguard sde-res sde-bindonly sde-kid sde-adult sde-tools >/dev/null 2>&1
    docker network rm spike_dnse_a spike_dnse_b >/dev/null 2>&1
}
cleanup
mkdir -p "$W"
[ "${KEEP_RAW:-}" ] || rm -rf "$W/raw"
rm -rf "$W/conf" "$W/ag" "$W/log"            # KEEP_RAW keeps only the downloaded lists
mkdir -p "$W/raw" "$W/conf" "$W/ag/work" "$W/ag/conf" "$W/log"
chmod 777 "$W/log"

echo "--- the lists, downloaded once"
for i in "${IDS[@]}" "$MORE"; do
    [ -s "$W/raw/filter_$i.txt" ] || curl -fsSL -o "$W/raw/filter_$i.txt" "$REG/filter_$i.txt" \
        || echo "  list $i: download failed"
done
ls -1 "$W/raw" | wc -l | xargs echo "  lists downloaded:"

docker build -q -t "$TOOLS" - >/dev/null <<'EOF' || exit 1
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends dnsutils dnsperf python3 curl ca-certificates bc \
    && rm -rf /var/lib/apt/lists/*
EOF
docker network create --subnet "$A.0/24" spike_dnse_a >/dev/null
docker network create --subnet "$B.0/24" spike_dnse_b >/dev/null
docker run -d --name sde-web --network spike_dnse_a --ip "$A.40" -v "$W/raw:/srv:ro" "$TOOLS" \
    python3 -m http.server 80 --directory /srv >/dev/null
for c in tools:200 kid:101 adult:102; do
    docker run -d --name "sde-${c%%:*}" --network spike_dnse_a --ip "$A.${c##*:}" "$TOOLS" sleep infinity >/dev/null
done

# ---- the authoritative BIND: fabric's zone
C=$W/conf
docker run --rm -v "$C:/out" "$BIND_IMAGE" rndc-confgen -a -c /out/rndc.key >/dev/null 2>&1; chmod 644 "$C/rndc.key"
cat > "$C/auth.conf" <<'EOF'
options { directory "/var/cache/bind"; recursion no; allow-query { any; }; listen-on-v6 { none; }; };
zone "site.test" { type primary; file "/etc/bind/x/site.test.db"; };
EOF
cat > "$C/site.test.db" <<EOF
\$TTL 300
@ SOA ns.site.test. hostmaster.site.test. 1 3600 600 86400 300
@ NS ns.site.test.
ns A $A.10
www A 10.1.2.3
EOF
printf '%s\n' '$TTL 300' '@ SOA localhost. hostmaster.fabric.rpz. 1 3600 600 86400 300' '@ NS localhost.' \
    'site.test CNAME rpz-passthru.' '*.site.test CNAME rpz-passthru.' > "$C/fabric.rpz"
printf '%s\n' '$TTL 300' '@ SOA localhost. hostmaster.owner.rpz. 1 3600 600 86400 300' '@ NS localhost.' \
    'blocked-by-owner.example CNAME .' '*.blocked-by-owner.example CNAME .' > "$C/owner.rpz"
docker run -d --name sde-auth --network spike_dnse_a --ip "$A.10" -v "$C:/etc/bind/x:ro" "$BIND_IMAGE" \
    named -f -u bind -c /etc/bind/x/auth.conf >/dev/null

# ---- A: AdGuard Home, as a non-root user, every capability dropped but NET_BIND_SERVICE (its binary carries it as a
# file capability: without it in the bounding set the kernel refuses to run it), on both networks
openssl rand -hex 16 > "$W/ag.pw"; chmod 600 "$W/ag.pw"
# Purpose: (re)create AdGuard Home's container: $1 the user ("" = root, its first launch only).
adguard() {
    docker rm -f sde-adguard >/dev/null 2>&1
    docker create --name sde-adguard --network spike_dnse_a --ip "$A.20" ${1:+--user "$1"} --cap-drop ALL \
        --cap-add NET_BIND_SERVICE --security-opt no-new-privileges:true \
        --sysctl net.ipv4.ip_unprivileged_port_start=53 -v "$W/ag/work:/opt/adguardhome/work" -v "$W/ag/conf:/opt/adguardhome/conf" "$AG_IMAGE" \
        --no-check-update --no-permcheck -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/work >/dev/null
    docker network connect --ip "$B.20" spike_dnse_b sde-adguard
    docker start sde-adguard >/dev/null
    for _ in $(seq 1 60); do curl -s -o /dev/null "http://$A.20:3000/" && break; sleep 1; done
}
AG() { python3 "$HERE/adguard.py" "http://$A.20:3000" "$W/ag.pw" "$@"; }
# findings: its first launch (no AdGuardHome.yaml yet) refuses any user but root, --no-permcheck or not ("you must
# run it as administrator"); root with every capability dropped cannot write folders it does not own; as nobody,
# no-new-privileges (rightly) voids the binary's file capability, so port 53 needs the namespace's
# ip_unprivileged_port_start instead, and NET_BIND_SERVICE stays in the bounding set only so exec is allowed.
# Here the first launch runs once as root on root-owned folders; fabric would render AdGuardHome.yaml itself, so
# there is no first launch. Then nobody, for good.
echo "--- A: AdGuard Home set up through its API (first launch as root), then run as nobody"
chown -R 0:0 "$W/ag"
adguard ""
AG setup
chown -R 65534:65534 "$W/ag"
adguard 65534:65534
docker ps --filter name=sde-adguard --format '  {{.Names}} {{.Status}}'
check "AdGuard Home runs as a non-root user once set up" \
    "[ \"\$(docker exec sde-adguard id -u)\" = 65534 ]"
echo "  memory, empty: $(mem sde-adguard)"
echo "--- A: the 15 lists added through the API"
AG lists "http://$A.40" "${IDS[@]}" | tail -1 | tee "$W/ag-lists.json"
sleep 5
AG_MEM=$(mem sde-adguard); echo "  memory, 15 lists: $AG_MEM"

# ---- A: the resolver in front: views, forwarding to AdGuard, dnstap
cat > "$C/res.conf" <<EOF
include "/etc/bind/x/rndc.key";
controls { inet 127.0.0.1 allow { localhost; } keys { "rndc-key"; }; };
options { directory "/var/cache/bind"; listen-on { any; }; listen-on-v6 { none; }; recursion yes;
  allow-query { $A.0/24; }; dnssec-validation no; max-cache-size 64m;
  dnstap { client response; }; dnstap-output file "/var/log/named/dnstap.log"; };
logging { channel q { file "/var/log/named/query.log"; print-time yes; };
  category queries { q; }; category rpz { q; }; };
view "kids" { match-clients { $A.101; }; forward only; forwarders { $B.20; };
  zone "site.test" { type forward; forward only; forwarders { $A.10; }; };
  zone "fabric.rpz" { type primary; file "/etc/bind/x/fabric.rpz"; };
  zone "owner.rpz" { type primary; file "/etc/bind/x/owner.rpz"; };
  response-policy { zone "fabric.rpz"; zone "owner.rpz"; } break-dnssec yes qname-wait-recurse no; };
view "main" { match-clients { any; }; forward only; forwarders { $A.20; };
  zone "site.test" { type forward; forward only; forwarders { $A.10; }; };
  zone "fabric.rpz" { type primary; file "/etc/bind/x/fabric.rpz"; };
  zone "owner.rpz" { type primary; file "/etc/bind/x/owner.rpz"; };
  response-policy { zone "fabric.rpz"; zone "owner.rpz"; } break-dnssec yes qname-wait-recurse no; };
EOF
docker create --name sde-res --network spike_dnse_a --ip "$A.30" -v "$C:/etc/bind/x:ro" -v "$W/log:/var/log/named" \
    "$BIND_IMAGE" named -f -u bind -c /etc/bind/x/res.conf >/dev/null
docker network connect --ip "$B.30" spike_dnse_b sde-res
docker start sde-res >/dev/null; sleep 3

BLOCKED=$(grep -m1 -E '^\|\|[a-z0-9.-]+\^$' "$W/raw/filter_1.txt" | tr -d '|^')
echo "--- A: checks through the resolver (a blocked name from list 1: $BLOCKED)"
check "fabric's zone answers from BIND though AdGuard has a rule blocking it" \
    "q sde-tools $A.30 www.site.test +short | grep -qx 10.1.2.3"
check "a listed name is blocked (NXDOMAIN) through BIND, by AdGuard" \
    "q sde-tools $A.30 $BLOCKED | grep -q 'status: NXDOMAIN'"
check "an ordinary name resolves" "q sde-tools $A.30 example.com | grep -q 'status: NOERROR'"
check "the owner's rule blocks in BIND, and BIND's log names it" \
    "q sde-tools $A.30 blocked-by-owner.example | grep -q 'status: NXDOMAIN' && sleep 1 && grep -q 'blocked-by-owner.example.*owner.rpz' '$W/log/query.log'"
check "the group: wikipedia.org blocked for the kids' view (AdGuard's rule for that client), not for others" \
    "q sde-kid $A.30 wikipedia.org | grep -q 'status: NXDOMAIN' && q sde-adult $A.30 wikipedia.org | grep -q 'status: NOERROR'"
echo "  the blocked answer's authority section (the marker):"
q sde-tools $A.30 "$BLOCKED" | sed -n '/AUTHORITY SECTION/,/^$/p' | sed 's/^/    /'
echo "  a genuine NXDOMAIN's authority section:"
q sde-tools $A.30 "no-such-name-$RANDOM.example.com" | sed -n '/AUTHORITY SECTION/,/^$/p' | sed 's/^/    /'
docker exec sde-res rndc -k /etc/bind/x/rndc.key dnstap -roll >/dev/null 2>&1; sleep 1
docker exec sde-res sh -c 'dnstap-read -y /var/log/named/dnstap.log.0 2>/dev/null || dnstap-read -y /var/log/named/dnstap.log' \
    > "$W/dnstap.yaml" 2>&1
check "dnstap records the client, the name and NXDOMAIN for the blocked answer" \
    "grep -q '$BLOCKED' '$W/dnstap.yaml' && grep -q 'NXDOMAIN' '$W/dnstap.yaml'"
check "AdGuard's own query log and statistics are off" \
    "AG call GET /control/querylog/config | grep -q '\"enabled\": false' && AG call GET /control/stats/config | grep -q '\"enabled\": false'"
echo "  check_host for the blocked name: $(AG call GET "/control/filtering/check_host?name=$BLOCKED" | cut -c1-300)"

echo "--- A: one more list (HaGeZi's Ultimate), then a list toggled off and on"
AG lists "http://$A.40" "$MORE" | tail -2
AG_MEM_MORE=$(mem sde-adguard); echo "  memory, 16 lists: $AG_MEM_MORE"
U="http://$A.40/filter_44.txt"
AG call POST /control/filtering/set_url "{\"url\": \"$U\", \"whitelist\": false, \"data\": {\"name\": \"list 44\", \"url\": \"$U\", \"enabled\": false}}" | cut -c1-120
AG call POST /control/filtering/set_url "{\"url\": \"$U\", \"whitelist\": false, \"data\": {\"name\": \"list 44\", \"url\": \"$U\", \"enabled\": true}}" | cut -c1-120

# ---- B: BIND alone, the same lists merged and deduplicated
echo "--- B: the same 15 lists, fabric's converter, merged into one zone"
python3 "$HERE/merge.py" "$W/raw" "$C/merged.rpz" "${IDS[@]}" | tee "$W/merge.json"
cat > "$C/bindonly.conf" <<EOF
include "/etc/bind/x/rndc.key";
controls { inet 127.0.0.1 allow { localhost; } keys { "rndc-key"; }; };
tls cloudflare { ca-file "/etc/ssl/certs/ca-certificates.crt"; remote-hostname "one.one.one.one"; };
options { directory "/var/cache/bind"; listen-on { any; }; listen-on-v6 { none; }; recursion yes;
  allow-query { $A.0/24; }; dnssec-validation auto; max-cache-size 64m;
  forward only; forwarders port 853 tls cloudflare { 1.1.1.1; 1.0.0.1; };
  response-policy { zone "fabric.rpz"; zone "merged.rpz"; } break-dnssec yes qname-wait-recurse no; };
zone "site.test" { type forward; forward only; forwarders { $A.10; }; };
zone "fabric.rpz" { type primary; file "/etc/bind/x/fabric.rpz"; };
zone "merged.rpz" { type primary; file "/etc/bind/x/merged.rpz"; };
EOF
docker run -d --name sde-bindonly --network spike_dnse_a --ip "$A.50" -v "$C:/etc/bind/x:ro" "$BIND_IMAGE" \
    named -f -u bind -c /etc/bind/x/bindonly.conf >/dev/null
B_LOAD=$(wait_status "$A.50" "$BLOCKED" NXDOMAIN); echo "  load: ${B_LOAD}s"
sleep 5; B_MEM=$(mem sde-bindonly); echo "  memory, 15 lists merged: $B_MEM"
echo "--- B: one more list: merge again and reload"
t0=$(date +%s.%N)
python3 "$HERE/merge.py" "$W/raw" "$C/merged.rpz" "${IDS[@]}" "$MORE" > "$W/merge-more.json"
sed -i '2s/ 1 3600/ 2 3600/' "$C/merged.rpz"          # a new serial: the reload is done when BIND serves it
docker exec sde-bindonly rndc -k /etc/bind/x/rndc.key reload merged.rpz >/dev/null
for _ in $(seq 1 3000); do docker exec sde-bindonly rndc -k /etc/bind/x/rndc.key zonestatus merged.rpz 2>/dev/null | grep -q '^serial: 2' && break; sleep 0.2; done
B_MORE=$(echo "$(date +%s.%N) - $t0" | bc)
echo "  merge + reload: ${B_MORE}s; memory, 16 lists: $(mem sde-bindonly); $(cut -c1-200 "$W/merge-more.json" | grep -o '"records_merged": [0-9]*')"

# ---- answer times, the same names through both
echo "--- answer times (dnsperf, 15 s at 300 queries/s each)"
python3 - "$C/merged.rpz" "$W/blocked.q" <<'PY'
import random, sys
names = [l.split()[0] for l in open(sys.argv[1]) if l.endswith("CNAME .\n") and not l.startswith("*")]
random.seed(7)
open(sys.argv[2], "w").writelines(f"{n} A\n" for n in random.sample(names, 5000))
PY
printf '%s A\n' example.com wikipedia.org github.com debian.org ubuntu.com cloudflare.com mozilla.org python.org \
    kernel.org gnu.org apache.org nginx.org isc.org nlnetlabs.nl iana.org ietf.org w3.org openssl.org > "$W/allowed.q"
docker cp "$W/blocked.q" sde-tools:/blocked.q >/dev/null; docker cp "$W/allowed.q" sde-tools:/allowed.q >/dev/null
for target in "A:$A.30" "B:$A.50"; do
    for f in blocked allowed; do
        out=$(docker exec sde-tools dnsperf -s "${target#*:}" -d "/$f.q" -l 15 -Q 300 -c 4 2>&1)
        echo "  ${target%%:*} $f: $(echo "$out" | grep -E 'Average Latency' | sed 's/^ *//'); lost $(echo "$out" | grep -o 'Queries lost: *[0-9]*' | grep -o '[0-9]*$')"
    done
done

echo "--- restarts: until a listed name is blocked again"
docker restart sde-adguard >/dev/null; echo "  A (AdGuard): $(wait_status "$A.20" "$BLOCKED" NXDOMAIN)s, memory $(mem sde-adguard)"
docker restart sde-bindonly >/dev/null; echo "  B (BIND alone): $(wait_status "$A.50" "$BLOCKED" NXDOMAIN)s, memory $(mem sde-bindonly)"
echo "  A's resolver in front: $(mem sde-res)"

echo; echo "$FAILED failed   (work: $W)"
[ "${KEEP:-}" ] || cleanup
