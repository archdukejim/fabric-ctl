#!/bin/bash
# The two points 1.12.3.14 asks to confirm before building (decision 2.1.12.6). Throwaway (global Rule 4).
#   1. A group's view forwards to AdGuard Home over DoT naming the group in the TLS server name (BIND's tls
#      remote-hostname); AdGuard takes it as the client's ID and applies that client's rule.
#   2. AdGuard Home reads a list from a file (safe_fs_patterns) instead of a URL.
#     bash spikes/dns-engine/clientid.sh        (needs run.sh's images: fabric-spike/bind9-dnsfilter, fabric-spike/dns-tools)
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=${SPIKE_DIR:-$HOME/fabric-spike-dns}/clientid
AG_IMAGE=${AG_IMAGE:-adguard/adguardhome@sha256:aba9e3bf0613be3ba3755e1fc311b126e2c24bec25e18b6483894a88283074f0}
BIND_IMAGE=fabric-spike/bind9-dnsfilter
TOOLS=fabric-spike/dns-tools
A=172.30.56
FAILED=0
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; FAILED=$((FAILED + 1)); fi; }
q() { docker exec "$1" dig +time=5 +tries=1 "@$2" "${@:3}"; }
cleanup() {
    docker rm -f sdc-adguard sdc-res sdc-kid sdc-adult >/dev/null 2>&1
    docker network rm spike_dnsc >/dev/null 2>&1
}
cleanup
rm -rf "$W"; mkdir -p "$W/ag/work" "$W/ag/conf" "$W/conf" "$W/lists" "$W/tls"
docker network create --subnet "$A.0/24" spike_dnsc >/dev/null

# a CA and a wildcard certificate for the groups' ClientIDs (*.filter.site.test)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=spike CA" \
    -keyout "$W/tls/ca.key" -out "$W/tls/ca.crt" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=filter.site.test" \
    -keyout "$W/tls/filter.key" -out "$W/tls/filter.csr" 2>/dev/null
printf 'subjectAltName=DNS:filter.site.test,DNS:*.filter.site.test\n' > "$W/tls/ext"
openssl x509 -req -in "$W/tls/filter.csr" -CA "$W/tls/ca.crt" -CAkey "$W/tls/ca.key" -CAcreateserial -days 2 \
    -extfile "$W/tls/ext" -out "$W/tls/filter.crt" 2>/dev/null
# a list as a file: blocks example.org for everyone
printf '||example.org^\n' > "$W/lists/local.txt"
chmod -R a+rX "$W/lists" "$W/tls"

# AdGuard Home: first launch as root on root-owned folders (fabric renders the file instead, 1.12.3.4)
openssl rand -hex 16 > "$W/ag.pw"; chmod 600 "$W/ag.pw"
docker run -d --name sdc-adguard --network spike_dnsc --ip "$A.20" --cap-drop ALL --cap-add NET_BIND_SERVICE \
    --security-opt no-new-privileges:true -v "$W/ag/work:/opt/adguardhome/work" -v "$W/ag/conf:/opt/adguardhome/conf" \
    -v "$W/lists:/lists:ro" -v "$W/tls:/tls:ro" "$AG_IMAGE" >/dev/null
for _ in $(seq 1 30); do curl -s -o /dev/null "http://$A.20:3000/" && break; sleep 1; done
AG() { python3 "$HERE/adguard.py" "http://$A.20:3000" "$W/ag.pw" "$@"; }
AG setup >/dev/null
# the groups' client: its ID, not an address; its own rule
AG call POST /control/clients/delete '{"name": "kids"}' >/dev/null
AG call POST /control/clients/add '{"name": "kids", "ids": ["kids"], "use_global_settings": true, "filtering_enabled": true, "parental_enabled": false, "safebrowsing_enabled": false, "safe_search": {"enabled": false}, "use_global_blocked_services": true, "blocked_services": [], "upstreams": [], "tags": []}' | cut -c1-120
AG call POST /control/filtering/set_rules '{"rules": ["||wikipedia.org^$client='"'"'kids'"'"'"]}' | cut -c1-120
# DoT on 853 with the wildcard certificate, its server name the base of the ClientIDs
# by path, as fabric would render it (the API takes inline PEM only base64-encoded)
AG call POST /control/tls/configure '{"enabled": true, "server_name": "filter.site.test", "force_https": false, "port_https": 0, "port_dns_over_tls": 853, "port_dns_over_quic": 0, "certificate_chain": "", "private_key": "", "certificate_path": "/tls/filter.crt", "private_key_path": "/tls/filter.key", "serve_plain_dns": true}' | cut -c1-300
# the list as a file: safe_fs_patterns must allow the folder (set in the file: the API cannot)
docker stop sdc-adguard >/dev/null
python3 - "$W/ag/conf/AdGuardHome.yaml" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
s = re.sub(r"(\n  safe_fs_patterns:\n)((?:    - .*\n)*)", r"\1    - /lists/*\n", s) if "safe_fs_patterns:" in s else s
open(p, "w").write(s)
PY
grep -n -A2 "safe_fs_patterns" "$W/ag/conf/AdGuardHome.yaml" | head -4
docker start sdc-adguard >/dev/null
for _ in $(seq 1 30); do curl -s -o /dev/null "http://$A.20:3000/" && break; sleep 1; done
AG call POST /control/filtering/add_url '{"name": "local", "url": "/lists/local.txt", "whitelist": false}' | cut -c1-200

# the resolver: the kids' view forwards over DoT naming its group; the main view over plain DNS
cp "$W/tls/ca.crt" "$W/conf/ca.crt"
cat > "$W/conf/res.conf" <<EOF
tls kids { ca-file "/etc/bind/x/ca.crt"; remote-hostname "kids.filter.site.test"; };
options { directory "/var/cache/bind"; listen-on { any; }; listen-on-v6 { none; }; recursion yes;
  allow-query { $A.0/24; }; dnssec-validation no; };
view "kids" { match-clients { $A.101; }; forward only; forwarders port 853 tls kids { $A.20; }; };
view "main" { match-clients { any; }; forward only; forwarders { $A.20; }; };
EOF
docker run -d --name sdc-res --network spike_dnsc --ip "$A.30" -v "$W/conf:/etc/bind/x:ro" "$BIND_IMAGE" \
    named -f -u bind -c /etc/bind/x/res.conf >/dev/null
for c in kid:101 adult:102; do
    docker run -d --name "sdc-${c%%:*}" --network spike_dnsc --ip "$A.${c##*:}" "$TOOLS" sleep infinity >/dev/null
done
sleep 3

echo "--- checks"
check "1. the kids' view (DoT, ClientID kids) gets the kids' rule: wikipedia.org NXDOMAIN" \
    "q sdc-kid $A.30 wikipedia.org | grep -q 'status: NXDOMAIN'"
check "1. the main view (plain DNS) does not: wikipedia.org resolves" \
    "q sdc-adult $A.30 wikipedia.org | grep -q 'status: NOERROR'"
check "1. the kids' view still resolves an ordinary name over DoT" \
    "q sdc-kid $A.30 example.com | grep -q 'status: NOERROR'"
check "2. the list read from a file blocks example.org for everyone" \
    "q sdc-adult $A.30 example.org | grep -q 'status: NXDOMAIN' && q sdc-kid $A.30 example.org | grep -q 'status: NXDOMAIN'"
echo "  example.org straight from AdGuard: $(q sdc-adult $A.20 example.org | grep -o 'status: [A-Z]*')"
echo "  AdGuard's filters: $(AG call GET /control/filtering/status | grep -o '"filters": \[[^]]*' | cut -c1-300)"
echo "  check_host for the kids' rule: $(AG call GET '/control/filtering/check_host?name=wikipedia.org&client=kids' | cut -c1-200)"
echo; echo "$FAILED failed   (work: $W)"
[ "${KEEP:-}" ] || cleanup
