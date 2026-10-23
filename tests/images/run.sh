#!/bin/bash
# -----------------------------------------------------------------------
# The images suite (decision 2.1.1.21, manual 3.14.1, 1.14.3): which image a host
# runs (published.py), signature verification (verify.py, needs network),
# and fabric's own images building from packaging/docker-bake.hcl the way
# CI publishes them, with the same build inputs a host with the default
# ids uses (its rendered compose files), each passing the smoke test CI
# runs before publishing. Builds for this machine's platform only (CI
# builds both on native runners).
#   sudo tests/run-all.sh images
# -----------------------------------------------------------------------
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FABRIC_TEST_OUT:-/tmp/fabric-tests}"
W="$OUT/images"
IMAGES=(bind9 freeradius kea keycloak samba stepca webui)
PASS=0; FAIL=0
check() { if eval "$2"; then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
rm -rf "$W"; mkdir -p "$W"
cd "$REPO" || exit 1

set -a
# shellcheck disable=SC1090  # the lock's build inputs, generated
. <(python3 packaging/images/bake_env.py)
CONTEXTS="$W/contexts"; REGISTRY=fabric-test/images; TAG="test"
set +a
# the contexts are staged outside the checkout: bake reads them only when allowed
BAKE=(docker buildx bake -f packaging/docker-bake.hcl "--allow=fs.read=$CONTEXTS")

# hosts: which image a host runs (rendered), and signature verification against real signatures (manual 1.14.3)
python3 tests/images/published.py
python3 tests/images/verify.py
# offline install bundles: export, the checks and refusals (2.1.14.14, manual 1.14.4); loading them is offline.sh's
python3 tests/images/bundle.py
# fabricctl images: routing, refusals, and prune on images only it makes (real Docker)
python3 tests/images/commands.py
# an image switch waits for the services restarted with the moved one (2.3.1.21.1)
python3 tests/images/switch_image_test.py

check "the build contexts stage from the assembled tree" "bash packaging/images/stage-contexts.sh \"\$CONTEXTS\" >/dev/null"
"${BAKE[@]}" --print >"$W/plan.json" 2>/dev/null
check "the build plan has every image" \
    "python3 -c 'import json,sys; t=json.load(open(sys.argv[1]))[\"target\"]; sys.exit(sorted(t) != sys.argv[2:])' \
     \"\$W/plan.json\" ${IMAGES[*]}"

# the bake inputs against the rendered compose files of a host with the default ids: the same base, the same
# pinned package and build revision, and ids that are the Dockerfiles' defaults
# (rendered with the lock's published digests blanked: what a host builds when it cannot use a published image)
mkdir -p "$W/tree/config"; ln -s "$REPO/templates" "$W/tree/templates"
sed -E 's/(tag: )"[^"]*", (digest: )"[^"]*"/\1"", \2""/' config/images.lock.yaml > "$W/tree/config/images.lock.yaml"
FABRIC_TEST_TEMPLATES="$W/tree/templates" python3 tests/render.py "$W/rendered" >/dev/null || echo "FAIL render"
parity() {
    python3 - "$W/plan.json" "$W/rendered" "$CONTEXTS" <<'PY'
import json, os, re, sys
import yaml
plan, rendered, contexts = json.load(open(sys.argv[1]))["target"], sys.argv[2], sys.argv[3]
bad = []
for name, target in plan.items():
    compose = yaml.safe_load(open(os.path.join(rendered, name, "docker-compose.yml")))
    want = next(s["build"]["args"] for s in compose["services"].values() if "build" in s)
    dockerfile = open(os.path.join(contexts, name, "Dockerfile")).read()
    defaults = dict(re.findall(r"^ARG (\w+)=(\S+)$", dockerfile, re.M))
    got = {**{k: v for k, v in defaults.items() if k.endswith(("_UID", "_GID"))}, **target.get("args", {})}
    if {k: str(v) for k, v in want.items()} != got:
        bad.append(f"{name}: compose {want} != bake {got}")
    if "@sha256:" not in got.get("BASE_IMAGE", ""):
        bad.append(f"{name}: base not pinned by digest")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
check "every image's build inputs match a default host's compose file: $(parity | tr -d '\n')" "parity >/dev/null"

check "an empty base refuses to build (nothing unpinned)" \
    "! BASE_DEBIAN= \"\${BAKE[@]}\" bind9 >\"\$W/unpinned.log\" 2>&1 && grep -q 'should not be blank' \"\$W/unpinned.log\""

check "every image builds" "\"\${BAKE[@]}\" --load >\"\$W/build.log\" 2>&1 || { tail -20 \"\$W/build.log\"; false; }"
for name in "${IMAGES[@]}"; do
    check "$name passes the smoke test" "bash packaging/images/smoke-test.sh $name $REGISTRY/$name:$TAG"
done
check "the web UI image carries this checkout's app" \
    "[ \"\$(docker run --rm --entrypoint sha256sum $REGISTRY/webui:$TAG /app/webui/server.py | cut -d' ' -f1)\" = \
       \"\$(sha256sum src/ux/web/server.py | cut -d' ' -f1)\" ]"

# the smoke test must catch what it is for: the upstream step-ca binary carries a file capability, which a
# container with none and no-new-privileges refuses to run
stepca_upstream="$(python3 -c "import sys; sys.path.insert(0, 'src')
from fabriclib.common.read_images_lock import read_images_lock; print(read_images_lock('config')['stepca']['ref'])")"
check "the smoke test refuses the upstream step-ca (file capability, no fabric labels)" \
    "! bash packaging/images/smoke-test.sh stepca $stepca_upstream >\"\$W/upstream.log\" 2>&1"

for name in "${IMAGES[@]}"; do docker image rm "$REGISTRY/$name:$TAG" >/dev/null 2>&1; done
echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
