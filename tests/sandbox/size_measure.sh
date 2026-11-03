#!/bin/bash
# -----------------------------------------------------------------------
# The sizing model's measurements on the sandbox (manual 1.8.8.8, 2.3.8.5):
# a sandbox left running by `KEEP=1 tests/sandbox/run.sh` is filled to each
# size in turn, left to settle, then each container's memory and CPU read at
# rest; then again, at their highest, while size_load.py makes the console's
# directory reads in a loop for LOAD seconds (their times go to stderr).
# One tab-separated line per container, size and phase goes to stdout (the
# sandbox shares the kernel of WSL, so the host memory is not read: it would
# count the machine's other work):
#   people  phase  container  memory_MiB  cpu_percent
#
#   sudo [FILL=dc|agent] [LOAD=120] tests/sandbox/size_measure.sh [SIZES...]
#        (default sizes: 5 100 1000; FILL=dc, the default, fills in one batch
#        inside the DC with size_fill_dc.py; FILL=agent through fabric-agent's
#        path, one call per object, with size_fill.py; LOAD=0 skips the load)
# -----------------------------------------------------------------------
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
NAME=fabric-sandbox
SETTLE="${SETTLE:-90}"; LOAD="${LOAD:-120}"; FILL="${FILL:-dc}"
docker ps --format '{{.Names}}' | grep -qx "$NAME" || { echo "no running sandbox; run KEEP=1 tests/sandbox/run.sh" >&2; exit 2; }
case "$FILL" in dc|agent) ;; *) echo "FILL is dc or agent: $FILL" >&2; exit 2 ;; esac
case "$LOAD" in ''|*[!0-9]*) echo "LOAD is a number of seconds: $LOAD" >&2; exit 2 ;; esac
for f in size_fill.py size_fill_dc.py size_load.py; do
    docker cp "$REPO/tests/sandbox/$f" "$NAME:/root/$f" || exit 1
done
# the site, the DC and the users' gid, as fabric's own create_person reads them (only names and a number)
read -r SITE DC GID < <(docker exec "$NAME" python3 -c 'import yaml; v = yaml.safe_load(open("/opt/fabric/config/vars.yaml"))
print(v["site_name"], v["dc_name"], next((int(g["gidNumber"]) for g in v.get("ldap_groups") or [] if g["name"] == "users"), 5000))')
[[ "$SITE $DC $GID" =~ ^[A-Za-z0-9-]+\ [A-Za-z0-9-]+\ [0-9]+$ ]] || { echo "no site, DC and gid read from the sandbox" >&2; exit 1; }

# Purpose: each container's memory (MiB) and CPU, one line each, from the sandbox's own Docker.
stats() {   # $1 people, $2 phase
    docker exec "$NAME" docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}' |
        awk -F'\t' -v n="$1" -v p="$2" '{split($2, m, " "); v=m[1]; u=v; gsub(/[0-9.]/, "", u); gsub(/[^0-9.]/, "", v);
             if (u == "GiB") v *= 1024; else if (u == "KiB") v /= 1024; else if (u == "B") v /= 1048576;
             sub(/%/, "", $3); printf "%s\t%s\t%s\t%.1f\t%s\n", n, p, $1, v, $3}'
}

printf 'people\tphase\tcontainer\tmemory_MiB\tcpu_percent\n'
[ $# -gt 0 ] || set -- 5 100 1000
for size in "$@"; do
    case "$size" in ''|*[!0-9]*) echo "a size is a number of people: $size" >&2; exit 2 ;; esac
    if [ "$FILL" = dc ]; then
        # the DC's /fabric is read-only: the script goes in on standard input
        docker exec -i "$NAME" docker exec -i samba python3 - "$size" "$SITE" "$DC" "$GID" < "$REPO/tests/sandbox/size_fill_dc.py" >&2
    else
        docker exec "$NAME" python3 /root/size_fill.py "$size" >&2
    fi || { echo "filling to $size failed" >&2; exit 1; }
    sleep "$SETTLE"
    stats "$size" rest
    [ "$LOAD" -gt 0 ] || continue
    # under load: each container's highest memory and highest CPU among the readings taken while the reads run
    docker exec "$NAME" python3 /root/size_load.py "$LOAD" > >(sed "s/^/$size people: /" >&2) &
    loader=$!
    samples=$(mktemp)
    while kill -0 "$loader" 2>/dev/null; do stats "$size" load >> "$samples"; done
    wait "$loader" || { echo "the load at $size failed" >&2; rm -f -- "$samples"; exit 1; }
    awk -F'\t' '{if ($4 + 0 > mem[$3]) mem[$3] = $4 + 0; if ($5 + 0 > cpu[$3]) cpu[$3] = $5 + 0}
        END {for (c in mem) printf "%s\tload-peak\t%s\t%.1f\t%.1f\n", n, c, mem[c], cpu[c]}' n="$size" "$samples"
    rm -f -- "$samples"
done
