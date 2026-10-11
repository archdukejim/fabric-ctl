#!/bin/bash
# info.<domain>/certs/ (manual 1.5.1.5): every published CA format is real, is this CA's certificate,
# and is served with the right type, by name and by address, with the CRLs; ca.<domain> stays Step-CA's API and sends
# browsers here; certs.<domain> is gone (no server, no certificate, no redirect).
# Run on the fabric host:  certs_page_test.sh <info-host> <ca-host> <nginx-ip> <host-ip>
set -uo pipefail
INFO=$1 CA=$2 IP=$3 HOST_IP=$4
DOMAIN=${INFO#*.}
OLD=certs.$DOMAIN
ROOT=/opt/stepca/data/certs/root_ca.crt
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
PASS=0; FAIL=0
check() { if (set +o pipefail; eval "$2"); then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
get() {   # file -> saves body to $W/file, headers to $W/file.h
    curl -s --cacert "$ROOT" --resolve "$INFO:443:$IP" -D "$W/$1.h" -o "$W/$1" "https://$INFO/certs/$1"
}
fp() { openssl x509 -noout -fingerprint -sha256 "$@" | cut -d= -f2; }
ROOT_FP=$(fp -in "$ROOT")
INT_FP=$(openssl x509 -in /opt/stepca/data/certs/intermediate_ca.crt | fp)

for f in root-ca.crt root-ca.pem root-ca.cer root-ca.der intermediate-ca.crt intermediate-ca.pem intermediate-ca.cer \
         intermediate-ca.der ca-chain.pem ca-chain.p7b ca-certs.json index.html; do get "$f"; done

check "root-ca.crt: PEM, this CA's root" "[ \"\$(fp -in $W/root-ca.crt)\" = '$ROOT_FP' ]"
check "root-ca.cer: DER (Windows), same root" "[ \"\$(fp -inform DER -in $W/root-ca.cer)\" = '$ROOT_FP' ]"
check "root-ca.der: DER, same root" "[ \"\$(fp -inform DER -in $W/root-ca.der)\" = '$ROOT_FP' ]"
check "root-ca.pem: PEM text, same root" "[ \"\$(fp -in $W/root-ca.pem)\" = '$ROOT_FP' ]"
check "intermediate-ca.crt/.cer/.der/.pem: the intermediate, all four" \
    "[ \"\$(fp -in $W/intermediate-ca.crt)\" = '$INT_FP' ] && [ \"\$(fp -inform DER -in $W/intermediate-ca.cer)\" = '$INT_FP' ] && [ \"\$(fp -inform DER -in $W/intermediate-ca.der)\" = '$INT_FP' ] && [ \"\$(fp -in $W/intermediate-ca.pem)\" = '$INT_FP' ]"
check "intermediate is signed by the root" "openssl verify -CAfile $W/root-ca.crt $W/intermediate-ca.crt >/dev/null"
check "ca-chain.pem: intermediate then root" \
    "[ \$(grep -c 'BEGIN CERTIFICATE' $W/ca-chain.pem) = 2 ] && [ \"\$(fp -in $W/ca-chain.pem)\" = '$INT_FP' ]"
check "ca-chain.p7b: PKCS#7 with both certificates" \
    "[ \$(openssl pkcs7 -inform DER -in $W/ca-chain.p7b -print_certs | grep -c 'BEGIN CERTIFICATE') = 2 ]"
check "ca-certs.json: fingerprints match the certificates" \
    "python3 -c \"import json,sys; d=json.load(open('$W/ca-certs.json')); sys.exit(0 if d['root-ca']['sha256']=='$ROOT_FP' and d['intermediate-ca']['sha256']=='$INT_FP' and d['root-ca']['sha1'] else 1)\""
check ".crt/.cer/.der/.p7b download (attachment) with certificate MIME types" \
    "grep -qi 'content-type: application/x-x509-ca-cert' $W/root-ca.crt.h && grep -qi 'content-disposition: attachment' $W/root-ca.crt.h && grep -qi 'content-type: application/pkix-cert' $W/root-ca.cer.h && grep -qi 'content-disposition: attachment' $W/root-ca.der.h && grep -qi 'content-type: application/x-pkcs7-certificates' $W/ca-chain.p7b.h"
check ".pem shown as text in the browser (no download)" \
    "grep -qi 'content-type: text/plain' $W/root-ca.pem.h && ! grep -qi 'content-disposition' $W/root-ca.pem.h"
check "page offers Windows, Linux, PEM, DER and chain downloads" \
    "grep -q 'root-ca.cer' $W/index.html && grep -q 'root-ca.crt' $W/index.html && grep -q 'root-ca.pem' $W/index.html && grep -q 'root-ca.der' $W/index.html && grep -q 'ca-chain.p7b' $W/index.html"
check "ca.<domain>/ redirects browsers to the certificate page" \
    "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --cacert $ROOT --resolve $CA:443:$IP https://$CA/ | grep -qx \"302 https://$INFO/certs/\""
check "an old /certificates link on info.<domain> goes to the certificate page" \
    "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --cacert $ROOT --resolve $INFO:443:$IP https://$INFO/certificates | grep -qx \"301 https://$INFO/certs/\""
check "ca.<domain> ACME directory still served by Step-CA" \
    "curl -sf --cacert $ROOT --resolve $CA:443:$IP https://$CA/acme/acme/directory | grep -q newOrder"
check "plain HTTP by name: served, no redirect to HTTPS (clients do not trust the CA yet)" \
    "[ \"\$(curl -s -o /dev/null -w '%{http_code}' --resolve $INFO:80:$HOST_IP http://$INFO/certs/root-ca.crt)\" = 200 ] && [ \"\$(curl -s --resolve $INFO:80:$HOST_IP http://$INFO/certs/root-ca.pem | fp)\" = '$ROOT_FP' ]"
check "plain HTTP by IP, no DNS needed: http://<host_ip>/certs/" \
    "curl -s http://$HOST_IP/certs/ | grep -q 'root-ca.cer' && [ \"\$(curl -s http://$HOST_IP/certs/root-ca.cer | fp -inform DER)\" = '$ROOT_FP' ] && curl -sI http://$HOST_IP/certs/ca-chain.p7b | grep -qi 'content-type: application/x-pkcs7-certificates'"
check "other plain-HTTP hosts still redirect to HTTPS" \
    "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --resolve $CA:80:$HOST_IP http://$CA/ | grep -q '^301 https://'"
check "this host trusts the CA from its system store" \
    "curl -sf --resolve $INFO:443:$IP -o /dev/null https://$INFO/certs/root-ca.pem"
# the CRL (1.5.1.3) where every leaf's distribution point names it, by name and by address
curl -s --resolve "$INFO:80:$HOST_IP" -o "$W/crl.der" "http://$INFO/certs/crl/intermediate.crl"
check "the intermediate's CRL at http://info.<domain>/certs/crl/intermediate.crl: DER, signed by the intermediate" \
    "openssl crl -inform DER -in $W/crl.der -noout -CAfile /opt/stepca/data/certs/intermediate_ca.crt 2>&1 | grep -q 'verify OK'"
check "…and the same at http://<host_ip>/certs/crl/ (DER and PEM)" \
    "curl -s http://$HOST_IP/certs/crl/intermediate.crl | cmp -s - $W/crl.der && curl -s http://$HOST_IP/certs/crl/intermediate.pem | grep -q 'BEGIN X509 CRL'"
check "Step-CA's leaf template (hand-signed and offline leaves) names http://info.<domain>/certs/crl/intermediate.crl" \
    "grep -q '\"crlDistributionPoints\": \\[\"http://$INFO/certs/crl/intermediate.crl\"\\]' /opt/stepca/data/templates/certs/leaf.tpl && ! grep -q 'certs\\.$DOMAIN' /opt/stepca/data/templates/certs/leaf.tpl"
# certs.<domain> is gone, with no redirect (2.1.5.11)
check "negative: certs.<domain> over HTTPS has no certificate of its own (TLS refuses the name)" \
    "! curl -s --max-time 10 --cacert $ROOT --resolve $OLD:443:$IP -o /dev/null https://$OLD/root-ca.pem"
check "negative: certs.<domain> over plain HTTP serves no CA file (only the catch-all's redirect)" \
    "[ \"\$(curl -s -o /dev/null -w '%{http_code}' --resolve $OLD:80:$HOST_IP http://$OLD/root-ca.crt)\" != 200 ]"
check "negative: no certificate left for certs.<domain> and no nginx server for it" \
    "[ ! -e /opt/nginx/certs/$OLD ] && ! grep -q 'server_name $OLD' /opt/nginx/config/nginx.conf"
echo "$PASS passed, $FAIL failed"
exit $FAIL
