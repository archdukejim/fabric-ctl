#!/bin/bash
# -----------------------------------------------------------------------
# Give the apt repository's signing key fabric-ctl's name, keeping the same key (manual 3.14.1.6, decision 2.1.3.5):
# a new user ID, "fabric-ctl apt repository <apt@fabric-ctl.invalid>", made the primary one. The key, and so its
# fingerprint, stay the same: hosts that already trust it need nothing. The old user ID ("open-fabric apt
# repository") is kept, not primary, unless --revoke-old: the owner chose to revoke it (2.1.3.5, B; it cannot be undone).
#
#   bash scripts/release/rename-apt-key.sh <offline folder of make-apt-key.sh> [--revoke-old]
#
# From the offline copy make-apt-key.sh wrote (the private key and its passphrase): GitHub never gives the secret
# back. The renamed key goes back into the Actions secret GPG_PRIVATE_KEY through `gh secret set` on standard input
# (the passphrase is unchanged), and the offline folder gets the renamed copies beside the old ones. The next apt
# publish (3.14.1.4 step 4, or a release) exports public.key from the secret, so it carries the new name.
#
# Run it from Git Bash on the owner's PC, in the repository's folder, by hand (the repository's owner): agents do
# not handle signing keys. Needs gpg and an authenticated `gh` with admin rights on the repository.
# -----------------------------------------------------------------------
set -euo pipefail
KEEP="${1:?usage: rename-apt-key.sh <offline folder> [--revoke-old]}"
REVOKE_OLD=0; [ "${2:-}" = --revoke-old ] && REVOKE_OLD=1
REPO="${FABRIC_REPO:-archdukejim/fabric-ctl}"
FPR=9946C72491FC85485ACD879BD0DF2E75E6E73230
OLD_UID="open-fabric apt repository <apt@open-fabric.invalid>"
NEW_UID="fabric-ctl apt repository <apt@fabric-ctl.invalid>"
[ -f "$KEEP/open-fabric-apt-private.key" ] && [ -f "$KEEP/open-fabric-apt-passphrase.txt" ] ||
    { echo "refused: $KEEP has no open-fabric-apt-private.key and open-fabric-apt-passphrase.txt" >&2; exit 2; }
export GNUPGHOME
GNUPGHOME="$(mktemp -d)"
trap 'gpgconf --kill gpg-agent 2>/dev/null; rm -rf "${GNUPGHOME:?}"' EXIT
umask 077
G=(gpg --batch --pinentry-mode loopback --passphrase-file "$KEEP/open-fabric-apt-passphrase.txt")

"${G[@]}" --import "$KEEP/open-fabric-apt-private.key"
got="$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" {print $10; exit}')"
[ "$got" = "$FPR" ] || { echo "refused: the offline key is $got, not the repository's $FPR" >&2; exit 2; }
"${G[@]}" --quick-add-uid "$FPR" "$NEW_UID"
"${G[@]}" --quick-set-primary-uid "$FPR" "$NEW_UID"
[ "$REVOKE_OLD" -eq 1 ] && "${G[@]}" --quick-revoke-uid "$FPR" "$OLD_UID"
got="$(gpg --batch --with-colons --list-keys | awk -F: '$1 == "fpr" {print $10; exit}')"
[ "$got" = "$FPR" ] || { echo "stopped: the fingerprint changed ($got); nothing was stored" >&2; exit 1; }

"${G[@]}" --armor --export-secret-keys "$FPR" | gh secret set GPG_PRIVATE_KEY --repo "$REPO"
"${G[@]}" --armor --export-secret-keys "$FPR" > "$KEEP/fabric-ctl-apt-private.key"
cp "$KEEP/open-fabric-apt-passphrase.txt" "$KEEP/fabric-ctl-apt-passphrase.txt"
gpg --batch --armor --export "$FPR" > "$KEEP/fabric-ctl-apt-public.key"

echo "signing key $FPR: primary user ID now \"$NEW_UID\"; the old one $([ "$REVOKE_OLD" -eq 1 ] && echo revoked || echo kept)"
echo "stored as GPG_PRIVATE_KEY in $REPO's Actions secrets (GPG_PASSPHRASE unchanged)"
echo "offline copy in $KEEP: fabric-ctl-apt-private.key, fabric-ctl-apt-passphrase.txt, fabric-ctl-apt-public.key"
echo "  (the open-fabric-apt-* files and the revocation certificate stay: the same key)"
echo "next: the next apt publish exports public.key with the new name; then tests/release/apt_key_test.sh (3.14.1.6)"
