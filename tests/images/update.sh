#!/usr/bin/env bash
# Every image's update and rollback from one version back (decision 2.1.14.12, manual 3.1.2), on an installed fabric
# host: for each installed service whose image has a previous version in previous.yaml, the host is moved to it the
# way an update moves it, then the current pin returns ("a new list arrived"): status shows the update, update moves
# it (health-gated), rollback goes back, update again. The rest are listed as skipped with the reason. Then status
# must be all current and doctor must pass.
#
#   tests/images/update.sh --box <container>                     the sandbox (tests/sandbox/run.sh keeps it with KEEP=1)
#   tests/images/update.sh --ssh <user@host> [--key <file>]      a test host (never the production one)
#
# It changes the host's images and its installed lock, and puts the lock back as it found it.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PASS=0; FAIL=0
check() { if eval "$2"; then PASS=$((PASS + 1)); echo "PASS $1"; else FAIL=$((FAIL + 1)); echo "FAIL $1"; fi; }

case "${1:-}" in
  --box) BOX="$2"
         on_host() { docker exec "$BOX" bash -lc "$*"; }
         put() { docker cp "$1" "$BOX:$2"; } ;;
  --ssh) DEST="$2"; KEY=(); [ "${3:-}" = --key ] && KEY=(-i "$4")
         on_host() { ssh "${KEY[@]}" -o BatchMode=yes "$DEST" "sudo bash -lc $(printf '%q' "$*")"; }
         put() { scp -q "${KEY[@]}" "$1" "$DEST:/tmp/$(basename "$2")" && on_host "mv /tmp/$(basename "$2") $2"; } ;;
  *) sed -n '2,10p' "$0"; exit 2 ;;
esac

put "$HERE/host_images.py" /root/host_images.py
on_host 'cp /opt/fabric/images.lock.yaml /root/images.lock.before'
restore() { on_host 'cp /root/images.lock.before /opt/fabric/images.lock.yaml'; }
trap restore EXIT

row() {      # the status row of one service, as "<state>|<running ref>"
    on_host 'python3 /root/host_images.py status' | python3 -c "
import json, sys
for line in sys.stdin:
    r = json.loads(line)
    if r['service'] == '$1':
        print(f\"{r['state']}|{r['running'] or ''}\")"
}
running_is() { [ "$(row "$1" | cut -d'|' -f2)" = "$2" ]; }
# whether fabricctl said it moved this service: services sharing an image move together, named in one list
# ("updated bind9, resolver")
said() { echo "$out" | grep -Eq "$1 ([a-z0-9-]+, )*$service( |,|$)"; }

rows=$(on_host 'python3 /root/host_images.py status')
behind=$(echo "$rows" | grep -vc '"state": "current"')
check "images status: every installed service current before the test" "[ $behind -eq 0 ]"
while IFS='|' read -r service var; do
    prev=$(python3 -c "
import sys, yaml
p = yaml.safe_load(open('$HERE/previous.yaml'))
e = (p.get('previous') or {}).get('$var')
print(f\"{e['tag']} {e['digest']}\" if e else 'skip ' + ((p.get('skipped') or {}).get('$var') or
      'a base fabric builds a local image from: it moves only with a fabric release'))")
    if [ "${prev%% *}" = skip ]; then
        echo "SKIP $service ($var): ${prev#skip }"
        continue
    fi
    read -r ptag pdigest <<< "$prev"
    read -r ctag cdigest <<< "$(on_host "python3 /root/host_images.py pinned $var")"
    cur=$(row "$service" | cut -d'|' -f2)
    base="${cur%%@*}"; repo="${base%:*}"        # repo:tag@digest -> repo
    pref="$repo:$ptag@$pdigest"
    echo "--- $service: $cur  ->  $ptag and back"
    on_host "python3 /root/host_images.py pin $var $ptag $pdigest"
    out=$(on_host "fabricctl images update $service" 2>&1)
    check "$service: moved to the previous version ($ptag) by an update, healthy" \
        "said updated && running_is $service '$pref'"
    on_host "python3 /root/host_images.py pin $var $ctag $cdigest"
    check "$service: the current pin back: status shows the update" \
        "[ \"\$(row $service | cut -d'|' -f1)\" = 'update available' ]"
    out=$(on_host "fabricctl images update $service" 2>&1)
    check "$service: update to $ctag, healthy" "said updated && running_is $service '$cur'"
    out=$(on_host "fabricctl images rollback $service" 2>&1)
    check "$service: rollback to $ptag, healthy" \
        "said 'rolled back' && running_is $service '$pref'"
    out=$(on_host "fabricctl images update $service" 2>&1)
    check "$service: update again, current" "said updated && running_is $service '$cur'"
done < <(echo "$rows" | python3 -c "
import json, sys
for line in sys.stdin:
    r = json.loads(line)
    print(f\"{r['service']}|{r['var']}\")")

check "afterwards: every image current" "on_host 'fabricctl images status' | grep -q 'all images current'"
check "afterwards: doctor passes" "on_host 'fabricctl doctor' >/dev/null 2>&1"
echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
