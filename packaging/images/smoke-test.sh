#!/bin/bash
# -----------------------------------------------------------------------
# Smoke test one of fabric's own images before it is published (decision
# 2.1.1.21, manual 3.14.1): its program runs under the settings fabric runs it
# with — its service account, every capability dropped, no-new-privileges,
# a read-only root and no network — and the image carries the labels hosts
# read (the base it was built FROM, the ids baked in). Whether each
# service then works is for the suites (hardening, kea, freeradius, …).
#
#   packaging/images/smoke-test.sh <image name> <image ref>
#   e.g. packaging/images/smoke-test.sh bind9 ghcr.io/archdukejim/fabric-ctl/bind9:dev
# -----------------------------------------------------------------------
set -uo pipefail
NAME="${1:?usage: smoke-test.sh <image name> <image ref>}"
IMAGE="${2:?usage: smoke-test.sh <image name> <image ref>}"

# the user it runs as, the ids baked in (empty: none) and the program with its version flag; other services'
# groups baked in (only the DC)
groups=""
case "$NAME" in
    bind9)      user=600:600; ids=600:600;   run=(/usr/sbin/named -v) ;;
    # ns-slapd -v prints its version and exits 1: the version line is the proof
    freeradius) user=610:610; ids=610:610;   run=(/usr/sbin/freeradius -v) ;;
    kea)        user=609:609; ids=609:609;   run=(/usr/sbin/kea-dhcp-ddns -V) ;;
    keycloak)   user=604:0;   ids="";        run=(/opt/keycloak/bin/kc.sh --version) ;;
    samba)      user=0:0;     ids="";        run=(/usr/sbin/samba -V); groups="BIND_GID=600,RADIUS_GID=610" ;;
    stepca)     user=603:603; ids="";        run=(/usr/local/bin/step-ca version) ;;
    webui)      user=606:606; ids=606:606;   run=(/usr/bin/python3 /app/webui/server.py --help) ;;
    *) echo "unknown image $NAME" >&2; exit 2 ;;
esac

fail=0
# Purpose: report one smoke check and remember a failure.
# Inputs:  $1 — what was checked; $2 — 0 if it passed. Updates $fail.
# Returns: 0.
# Fails:   never.
# Feeds:   the checks below.
report() { if [ "$2" -eq 0 ]; then echo "PASS $NAME: $1"; else echo "FAIL $NAME: $1"; fail=1; fi; }

out=$(docker run --rm --network none --read-only --tmpfs /tmp:size=64m --cap-drop ALL \
      --security-opt no-new-privileges:true --user "$user" --entrypoint "${run[0]}" "$IMAGE" "${run[@]:1}" 2>&1)
rc=$?
[ "$rc" -eq 0 ] || echo "$out" | tail -5 | sed 's/^/    /'
report "${run[*]} runs as $user with no capabilities on a read-only root" "$rc"

# Purpose: one label of the image under test.
# Inputs:  $1 — the label's key. Asks Docker about $IMAGE.
# Returns: the label's value on stdout; nothing if the label or the image is missing.
# Fails:   never (docker errors print nothing).
# Feeds:   the label checks below.
label() { docker image inspect -f "{{index .Config.Labels \"$1\"}}" "$IMAGE" 2>/dev/null; }
[ -n "$(label org.fabric.base)" ]; report "names the base it was built FROM (org.fabric.base: $(label org.fabric.base))" $?
if [ -n "$ids" ]; then
    [ "$(label org.fabric.ids)" = "$ids" ]; report "has the default service account ids baked in ($ids)" $?
fi
if [ -n "$groups" ]; then
    [ "$(label org.fabric.groups)" = "$groups" ]; report "has the default groups of other services baked in ($groups)" $?
fi
exit "$fail"
