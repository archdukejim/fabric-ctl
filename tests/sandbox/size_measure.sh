#!/bin/bash
# -----------------------------------------------------------------------
# The sizing model's measurements on the sandbox (manual 1.8.8.8, 2.3.8.5):
# a sandbox left running by `KEEP=1 tests/sandbox/run.sh` is filled to each
# size in turn (tests/sandbox/size_fill.py tops up), left to settle, then each
# container's memory and CPU read at rest. One tab-separated line per
# container and size goes to stdout (the sandbox shares the kernel of WSL, so
# the host memory is not read: it would count the machine's other work):
#   people  container  memory_MiB  cpu_percent
#
#   sudo tests/sandbox/size_measure.sh [SIZES...]     (default: 5 100 1000)
# -----------------------------------------------------------------------
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
NAME=fabric-sandbox
SETTLE="${SETTLE:-90}"
docker ps --format '{{.Names}}' | grep -qx "$NAME" || { echo "no running sandbox; run KEEP=1 tests/sandbox/run.sh" >&2; exit 2; }
docker cp "$REPO/tests/sandbox/size_fill.py" "$NAME:/root/size_fill.py" || exit 1
[ $# -gt 0 ] || set -- 5 100 1000
printf 'people\tcontainer\tmemory_MiB\tcpu_percent\n'
for size in "$@"; do
    case "$size" in ''|*[!0-9]*) echo "a size is a number of people: $size" >&2; exit 2 ;; esac
    docker exec "$NAME" python3 /root/size_fill.py "$size" >&2 || { echo "filling to $size failed" >&2; exit 1; }
    sleep "$SETTLE"
    # docker stats' memory as "123.4MiB / 1GiB": the first figure, in MiB
    docker exec "$NAME" docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}' |
        awk -F'\t' -v n="$size" '{split($2, m, " "); v=m[1]; u=v; gsub(/[0-9.]/, "", u); gsub(/[^0-9.]/, "", v);
             if (u == "GiB") v *= 1024; else if (u == "KiB") v /= 1024; else if (u == "B") v /= 1048576;
             sub(/%/, "", $3); printf "%s\t%s\t%.1f\t%s\n", n, $1, v, $3}'
done
