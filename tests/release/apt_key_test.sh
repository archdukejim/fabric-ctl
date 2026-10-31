#!/bin/bash
# -----------------------------------------------------------------------
# The apt repository's public key keeps its fingerprint and carries fabric-ctl's name (manual 3.14.1.6, decision
# 2.1.3.5): the published public.key (or a file given) is the one key 9946C724…E6E73230, its primary user ID is
# "fabric-ctl apt repository <apt@fabric-ctl.invalid>", and the old "open-fabric apt repository" ID, kept or
# revoked, is not the primary one. Needs gpg and, for the published key, the network.
#
#   bash tests/release/apt_key_test.sh [<public.key file or URL>]     (default: the published one)
# -----------------------------------------------------------------------
set -uo pipefail
SRC="${1:-https://archdukejim.github.io/fabric-ctl/public.key}"
FPR="${APT_KEY_FPR:-9946C72491FC85485ACD879BD0DF2E75E6E73230}"   # another only to try the test on a throwaway key
NEW_UID="fabric-ctl apt repository <apt@fabric-ctl.invalid>"
OLD_NAME="open-fabric apt repository"
PASS=0; FAIL=0
check() { if (set +o pipefail; eval "$2"); then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); fi; }
export GNUPGHOME
GNUPGHOME="$(mktemp -d)"
trap 'gpgconf --kill gpg-agent 2>/dev/null; rm -rf "${GNUPGHOME:?}"' EXIT
case "$SRC" in
    http://*|https://*) curl -fsSL "$SRC" -o "$GNUPGHOME/public.key" || { echo "FAIL could not fetch $SRC"; exit 1; } ;;
    *) cp "$SRC" "$GNUPGHOME/public.key" ;;
esac
gpg --batch --quiet --import "$GNUPGHOME/public.key" 2>/dev/null
COLONS="$(gpg --batch --with-colons --list-keys --list-options show-unusable-uids)"
# the primary user ID is the first uid line gpg lists (it sorts the primary first); field 2 "r" marks a revoked one
uids() { printf '%s\n' "$COLONS" | awk -F: '$1 == "uid" {print $2 "|" $10}'; }
keys() { printf '%s\n' "$COLONS" | awk -F: '$1 == "pub" {n++} $1 == "fpr" && !f {f = $10} END {print n "|" f}'; }
primary() { uids | head -1; }

check "one key in it, and it is $FPR (the fingerprint hosts trust)" "[ \"\$(keys)\" = '1|$FPR' ]"
check "its primary user ID is \"$NEW_UID\", valid (not revoked)" \
    "p=\$(primary); [ \"\${p#*|}\" = '$NEW_UID' ] && [ \"\${p%%|*}\" != r ]"
check "negative: the old \"$OLD_NAME\" ID is not the primary one (kept below it, or revoked)" \
    "! primary | grep -qF '$OLD_NAME'"
echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
