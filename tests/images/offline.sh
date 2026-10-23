#!/bin/bash
# -----------------------------------------------------------------------
# An offline install from a bundle (decision 2.1.14.14, manual 1.14.4, 3.14.2), on a host with no way to the
# internet: a bare Ubuntu box with systemd and none of fabric's packages (tests/images/offline/Dockerfile) on a
# Docker network with no route out.
#   1. here, online: the .deb built from the working tree and `images export --deb <it> --allow-unpublished` for
#      this machine's architecture and Ubuntu release (an image the lock has not published is left out: this test
#      does not install it; --deb: this version is not released, 2.1.14.23)
#   2. in the box, offline: fabricctl installed from the bundle's own packages by the manual's procedure (3.14.2.2,
#      offline/bootstrap.sh); Docker and the host's packages by setup's `host` step from the bundle; `images
#      import` refused on Docker's classic store, for a missing file and when the store has not the room; then
#      imported, checked and loaded with nothing fetched, and a second import loading nothing; `setup --offline
#      <bundle>` installs fabric (the domain member's packages from the bundle too) and starts it with no image
#      pulled
#
#   sudo tests/images/offline.sh          (KEEP=1 leaves the box running; about 30 min and 6 GB in /var/tmp)
#
# Run alone: its box, network and volumes are its own (bundles-offline*), and it deletes them and the bundle.
# -----------------------------------------------------------------------
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FABRIC_TEST_OUT:-/tmp/fabric-tests}/bundles-offline"
WORK=/var/tmp/bundles-offline
NAME=bundles-offline
NET=bundles-offline-net
SUBNET=10.79.5.0/24
IP=10.79.5.10
VOLS=(bundles-offline-docker bundles-offline-containerd)
PASS=0; FAIL=0
check() { if (set +o pipefail; eval "$2"); then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
in_box() { docker exec "$NAME" bash -lc "$*"; }
cleanup() {
    [ "${KEEP:-0}" = 1 ] && { echo "kept: docker exec -it $NAME bash"; return; }
    docker rm -f "$NAME" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1
    docker volume rm "${VOLS[@]}" >/dev/null 2>&1; rm -rf "$WORK"
}
cleanup; rm -rf "$OUT"; mkdir -p "$OUT" "$WORK"
trap cleanup EXIT
ARCH="$(dpkg --print-architecture)"

# 1. online, on this machine
DEB=$(OUT="$WORK/dist" bash "$REPO/packaging/deb/build-deb.sh") || { echo "FAIL package build"; exit 1; }
echo "--- images export ($ARCH; --allow-unpublished: an image the lock has not published is left out, 2.1.14.21)"
# covers: cli:images.export +
python3 "$REPO/src/fabriclib/cli.py" images export --arch "$ARCH" -o "$WORK/fabric.tar" --deb "$DEB" \
    --allow-unpublished > "$OUT/export.log" 2>&1
check "the bundle is exported for $ARCH ($(du -h "$WORK/fabric.tar" 2>/dev/null | cut -f1))" "test -s '$WORK/fabric.tar'"
[ -s "$WORK/fabric.tar" ] || { tail -5 "$OUT/export.log"; exit 1; }

# 2. the box: no route out
docker build -q -t fabric/bundles-offline-host:local "$REPO/tests/images/offline" >/dev/null || { echo "FAIL box image"; exit 1; }
docker network create --internal --subnet "$SUBNET" "$NET" >/dev/null
# containerd's store on a volume of its own: on the box's own overlay root it cannot unpack layers
docker run -d --name "$NAME" --hostname fabric-off --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
  -v "${VOLS[0]}:/var/lib/docker" -v "${VOLS[1]}:/var/lib/containerd" --network "$NET" --ip "$IP" \
  fabric/bundles-offline-host:local >/dev/null
for _ in $(seq 1 30); do in_box 'systemctl is-system-running 2>/dev/null' | grep -qE 'running|degraded' && break; sleep 2; done
check "the box cannot reach the internet (ghcr.io, Docker Hub, Sigstore, Ubuntu's archive)" \
    "! in_box 'curl -sS -m 5 https://ghcr.io; curl -sS -m 5 https://registry-1.docker.io; curl -sS -m 5 https://tuf-repo-cdn.sigstore.dev; curl -sS -m 5 http://archive.ubuntu.com' >/dev/null 2>&1"
check "the box has no Docker and no fabricctl" "! in_box 'command -v docker || dpkg -s fabricctl' >/dev/null 2>&1"
docker cp "$WORK/fabric.tar" "$NAME:/root/fabric.tar"
docker cp "$REPO/tests/images/offline/bootstrap.sh" "$NAME:/root/bootstrap.sh"
rm -f "$WORK/fabric.tar"                    # the box has its copy; keep the disk use down
in_box 'ls -la /etc/apt/sources.list.d; cat /etc/apt/sources.list.d/* /etc/apt/sources.list 2>/dev/null' \
    > "$OUT/sources-before.txt"
in_box 'bash /root/bootstrap.sh /root/fabric.tar' > "$OUT/bootstrap.log" 2>&1
check "fabricctl installs offline from the bundle's own packages, apt checking Ubuntu's signatures (3.14.2.2)" \
    "in_box 'dpkg -s fabricctl' | grep -q '^Status: install ok installed' && ! grep -qiE 'NO_PUBKEY|not signed|signature' '$OUT/bootstrap.log' \
     && ! in_box 'test -e /var/tmp/fabric-apt'"
cat > "$OUT/vars.yaml" <<EOF
domain: off.test
hostname: fabric-off
host_ip: $IP
lan_cidr: $SUBNET
lan_gateway: 10.79.5.1
friendly_name: Offline
ad_domain: ad.off.test
install_keycloak: false
ntp_set_clock: false
dns_filter_lists: []
EOF
docker cp "$OUT/vars.yaml" "$NAME:/root/vars.yaml"
# covers: cli:setup +
in_box 'fabricctl setup --offline /root/fabric.tar --step host --file /root/vars.yaml --non-interactive --yes --approve all' \
    > "$OUT/setup-host.log" 2>&1
check "setup's host step installs Docker and the host's packages from the bundle, offline" \
    "grep -q 'from the offline bundle' '$OUT/setup-host.log' && in_box 'docker info' >/dev/null 2>&1 \
     && ! in_box 'ls /var/tmp | grep -q fabric-offline-apt'"
in_box 'ls -la /etc/apt/sources.list.d; cat /etc/apt/sources.list.d/* /etc/apt/sources.list 2>/dev/null' \
    > "$OUT/sources-after.txt"
check "the host's own apt sources are unchanged (nothing added or changed)" \
    "cmp -s '$OUT/sources-before.txt' '$OUT/sources-after.txt'"

# covers: cli:images.import -
in_box 'echo "{\"features\": {\"containerd-snapshotter\": false}}" > /etc/docker/daemon.json && systemctl restart docker'
in_box 'fabricctl images import /root/fabric.tar' > "$OUT/import-classic.log" 2>&1
check "on Docker's classic store the import is refused, saying why, nothing loaded" \
    "grep -q 'classic store' '$OUT/import-classic.log' && [ -z \"\$(in_box 'docker images -q')\" ]"
in_box 'rm -f /etc/docker/daemon.json && systemctl restart docker'
check "Docker is on the containerd store again" "in_box 'docker info -f \"{{json .DriverStatus}}\"' | grep -q containerd.snapshotter"
in_box 'fabricctl images import /root/nope.tar' > "$OUT/import-missing.log" 2>&1
check "a bundle that is not there is refused, saying so" "grep -q 'not a readable bundle' '$OUT/import-missing.log'"
in_box 'mkdir -p /root/tiny && mount -t tmpfs -o size=8m bundles-tiny /root/tiny && PYTHONPATH=/usr/lib/fabricctl/fabric/lib python3 -c "
from fabriclib.images.bundle.import_bundle import import_bundle
import_bundle(\"/root/fabric.tar\", \"/usr/lib/fabricctl/fabric\", store=\"/root/tiny\", log=lambda s: None)"; umount /root/tiny' \
    > "$OUT/import-space.log" 2>&1
check "an import without the room in Docker's store is refused, naming needed and free, nothing loaded" \
    "grep -q 'not enough space' '$OUT/import-space.log' && [ -z \"\$(in_box 'docker images -q')\" ]"
# covers: cli:images.import +
in_box 'fabricctl images import /root/fabric.tar' > "$OUT/import.log" 2>&1
check "images import, offline: every image loaded, the published images' signatures verified offline" \
    "grep -qE '^[0-9]+ image\(s\) loaded, 0 already present' '$OUT/import.log' \
     && grep -qE '^[1-9][0-9]* signature\(s\) of fabric.s published images verified offline' '$OUT/import.log'"
docker cp "$REPO/tests/images/offline/pinned_present.py" "$NAME:/root/pinned_present.py"
check "every image of the lock is known to Docker by its pinned digest" \
    "in_box 'python3 /root/pinned_present.py' > '$OUT/pinned.log' 2>&1"
check "the verified digests are remembered (root-only), so setup's online check is not needed" \
    "[ \"\$(in_box 'stat -c %a /etc/fabric/images/verified.json')\" = 600 ]"
in_box 'fabricctl images import /root/fabric.tar' > "$OUT/import-again.log" 2>&1
check "a second import loads nothing (idempotent)" "grep -qE '^0 image\(s\) loaded' '$OUT/import-again.log'"

# covers: cli:setup -
in_box 'fabricctl setup --offline /root/missing.tar --non-interactive --yes' > "$OUT/setup-missing.log" 2>&1
check "setup --offline with a bundle that is not there is refused before any step" \
    "grep -q 'no offline bundle at /root/missing.tar' '$OUT/setup-missing.log' && ! in_box 'test -e /opt/fabric/config/fabric.yaml'"

echo "--- setup --offline (about 15 min)"
# covers: cli:setup +
in_box 'fabricctl setup --offline /root/fabric.tar --file /root/vars.yaml --non-interactive --yes --approve all' \
    > "$OUT/setup.log" 2>&1
code=$?
check "setup --offline <bundle> installs fabric with no internet (exit $code)" "[ $code -eq 0 ]"
check "its member step installed the domain member's packages from the bundle" \
    "in_box 'dpkg -s sssd-ad' | grep -q '^Status: install ok installed'"
check "its bundle step checked the bundle and found the images already loaded" \
    "grep -q 'checking the offline bundle /root/fabric.tar' '$OUT/setup.log' && grep -qE '0 image\(s\) loaded' '$OUT/setup.log'"
check "nothing was pulled or built" "! grep -qE 'Pulling from|Building [a-z]' '$OUT/setup.log'"
check "fabric.target is active and doctor passes" \
    "in_box 'systemctl is-active fabric.target' | grep -qx active && in_box 'fabricctl doctor' > '$OUT/doctor.log' 2>&1"
check "status lists a bundle that left images out as relaxed (when the export left any out)" \
    "! grep -q 'left out (--allow-unpublished)' '$OUT/export.log' || in_box 'fabricctl status 2>&1' | grep -q 'allow-unpublished'"
check "BIND answers for the zone on the host's address" "in_box 'dig +short @$IP ns.off.test' | grep -qx '$IP'"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
