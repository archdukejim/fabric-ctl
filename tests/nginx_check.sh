#!/bin/bash
# nginx -t against the rendered config, with dummy certs at every referenced path; then the rendered config running
# in a real nginx, for what plain HTTP serves where (the landing page at /info/, 2.1.4.6, manual 1.4.2.5).
set -euo pipefail
R="$1/nginx"   # render.py output dir
W=$(mktemp -d)
rm -rf "$W"; mkdir -p "$W/certs" "$W/www" "$W/conf.d"
# the snippets setup writes at run time (nginx includes them by name)
echo "# test" > "$W/conf.d/client-crl.inc"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/k.pem" -out "$W/c.pem" -days 1 -subj /CN=x 2>/dev/null
grep -oE '/etc/nginx/certs/[^;]+' "$R/nginx.conf" | sort -u | while read -r p; do
  rel="${p#/etc/nginx/certs/}"; mkdir -p "$W/certs/$(dirname "$rel")"
  case "$p" in *privkey.pem) cp "$W/k.pem" "$W/certs/$rel" ;; *) cp "$W/c.pem" "$W/certs/$rel" ;; esac
done
IMAGE="$(python3 "$(dirname "$0")/image_ref.py" nginx)"
out=$(docker run --rm -v "$R/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$W/certs:/etc/nginx/certs:ro" -v "$W/conf.d:/etc/nginx/conf.d:ro" "$IMAGE" nginx -t 2>&1)
echo "$out" | grep -E 'nginx:'
grep -q 'test is successful' <<<"$out" || { rm -rf "$W"; echo "FAIL nginx -t"; exit 1; }
echo "PASS nginx -t"

# --- plain HTTP, served: the page by address and on any name, fabric's services to HTTPS, the CA files everywhere
read -r LAND STEPCA HOSTFQDN DOMAIN < <(python3 -c "
import sys, yaml
v = yaml.safe_load(open(sys.argv[1]))
print(v['hostname_landing'], v['hostname_stepca'], (v['hostname'] + '.' + v['domain']).lower(), v['domain'])
" "$1/vars.yaml")
mkdir -p "$W/www/landing" "$W/www/certs/crl" "$W/www/shared"
echo '<p>landing</p><script>fetch("/certs/ca-certs.json")</script>' > "$W/www/landing/index.html"
echo 'crl' > "$W/www/certs/crl/intermediate.crl"
echo 'body{}' > "$W/www/shared/style.css"
chmod -R a+rX "$W"
C="fabric-nginx-check-$$"
FAILED=0
cleanup() { docker rm -f "$C" >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT
docker run -d --name "$C" -v "$R/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$W/certs:/etc/nginx/certs:ro" \
  -v "$W/conf.d:/etc/nginx/conf.d:ro" -v "$W/www:/srv/www:ro" "$IMAGE" >/dev/null
for _ in $(seq 1 20); do
  docker exec "$C" curl -s -o /dev/null http://127.0.0.1/health && break
  sleep 0.5
done
# get <host> <path> -> "<code> <redirect>" (body to /tmp/body in the container)
get() { docker exec "$C" curl -s -o /tmp/body -w '%{http_code} %{redirect_url}' -H "Host: $1" "http://127.0.0.1$2" || true; }
body() { docker exec "$C" cat /tmp/body 2>/dev/null || true; }
check() {   # check <name> <what was got> <glob pattern it must match>
  # shellcheck disable=SC2053  # the pattern is a glob on purpose
  if [[ $2 == $3 ]]; then echo "PASS $1"; else echo "FAIL $1  -> $2"; FAILED=1; fi
}
r=$(get 192.168.7.53 /info/); b=$(body)
# covers: setting:hostname_landing +
check "http://<host_ip>/info/ serves the landing page" "$r|$b" "200 *|*landing*"
check "http://<host_ip>/info redirects to /info/" "$(get 192.168.7.53 /info)" "301 */info/"
check "http://<host_ip>/ goes to the landing page (/info/), not to HTTPS" "$(get 192.168.7.53 /)" "302 */info/"
check "an alias the admin points here (info renamed) shows the page at /info/" "$(get "welcome.$DOMAIN" /)" \
  "302 http://welcome.$DOMAIN/info/"
check "...its manual link goes to the host's own name over HTTPS" "$(get "welcome.$DOMAIN" /manual/)" \
  "301 https://$HOSTFQDN/manual/"
# covers: setting:hostname_stepca -
check "negative: a fabric service's name (ca.<domain>) still goes to HTTPS, not to the page" "$(get "$STEPCA" /)" \
  "301 https://$STEPCA/"
# covers: setting:hostname_stepca +
r=$(get "$STEPCA" /certs/crl/intermediate.crl); b=$(body)
check "the CRL point certificates name answers on plain HTTP (http://ca.<domain>/certs/crl/, 1.5.1.6)" "$r|$b" "200 *|crl"
for n in "$LAND" "$DOMAIN" "$HOSTFQDN"; do
  r=$(get "$n" /); b=$(body)
  check "$n/ serves the page itself over HTTP (no redirect to info.<domain>)" "$r|$b" "200 *|*landing*"
done
check "the 0.7.0 CRL point (info.<domain>) keeps answering while info points here" \
  "$(get "$LAND" /certs/crl/intermediate.crl)" "200 *"
# covers: setting:hostname_landing -
check "negative: the manual is not served over plain HTTP on the landing names (to HTTPS)" "$(get "$LAND" /manual/)" \
  "301 https://$LAND/manual/"
[ "$FAILED" = 0 ] || { echo "FAIL nginx: served HTTP"; exit 1; }
echo "PASS nginx: served HTTP"
