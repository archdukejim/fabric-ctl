#!/bin/bash
# -----------------------------------------------------------------------
# Web-guided setup as users get it (manual 1.3.6.8): the package from this
# tree in a disposable systemd + Docker sandbox, `fabricctl setup` in a real
# terminal, real ufw, and a real browser on the sandbox's network accepting
# every default through to a working install; first the collisions and
# refusals, each leaving nothing behind. About 40 min.
#
#   sudo tests/sandbox/web_guided.sh      (KEEP=1 leaves the sandbox running)
#
# Takes run.sh's lock, so one sandbox suite runs at a time. Needs privileged
# Docker on the machine running it.
# -----------------------------------------------------------------------
set -uo pipefail
exec 9>/tmp/fabric-sandbox-suite.lock
flock -n 9 || { echo "another sandbox run is active; refusing to start" >&2; exit 2; }
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FABRIC_TEST_OUT:-/tmp/fabric-tests}/web-guided"
NAME=fabric-sandbox-web
NET=fabric-sbx-web-net
VOLUME=fabric-sbx-web-docker
SUBNET=10.78.0.0/24
IP=10.78.0.10
in_box() { docker exec "$NAME" bash -lc "$*"; }
clean() {
    [ "${KEEP:-0}" = 1 ] && return
    docker rm -f "$NAME" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    docker volume rm "$VOLUME" >/dev/null 2>&1
}

KEEP=0 clean
case "$OUT" in /tmp/*) rm -rf "${OUT:?}" ;; esac
mkdir -p "$OUT"
docker build -q -t fabric/sandbox:local "$REPO/tests/sandbox" >/dev/null || { echo "FAIL sandbox image"; exit 1; }
docker network create --subnet "$SUBNET" --gateway 10.78.0.1 "$NET" >/dev/null
trap clean EXIT
# as run.sh: a private cgroup namespace, so restarting Docker inside never touches this machine's
docker run -d --name "$NAME" --hostname fabric-sbx --privileged --cgroupns=private \
  -v "$VOLUME:/var/lib/docker" \
  --tmpfs /run --tmpfs /run/lock --network "$NET" --ip "$IP" fabric/sandbox:local >/dev/null
for _ in $(seq 1 30); do in_box 'systemctl is-system-running 2>/dev/null' | grep -qE 'running|degraded' && break; sleep 2; done
in_box 'mkdir -p /etc/docker && echo "{\"features\": {\"containerd-snapshotter\": false}, \"storage-driver\": \"overlay2\"}" > /etc/docker/daemon.json'
# The one thing that is not a default: the sandbox shares this machine's kernel clock, and every default accepted would
# have chrony set it (run.sh says ntp_set_clock: false, which Guided does not ask). -x wins over the -s fabric writes.
in_box 'mkdir -p /etc/systemd/system/chrony.service.d && printf "[Service]\nExecStart=\nExecStart=!/usr/sbin/chronyd \$DAEMON_OPTS -x\n" > /etc/systemd/system/chrony.service.d/sandbox.conf'

DEB=$(OUT="$OUT/dist" bash "$REPO/packaging/deb/build-deb.sh") || { echo "FAIL package build"; exit 1; }
docker cp "$DEB" "$NAME:/root/fabricctl.deb"
in_box 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /root/fabricctl.deb ufw' > "$OUT/apt.log" 2>&1 \
    || { echo "FAIL package install"; tail -20 "$OUT/apt.log"; exit 1; }

python3 "$REPO/tests/sandbox/web_guided_drive.py" "$NAME" "$NET" "$IP" "$OUT"
