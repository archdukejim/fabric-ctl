#!/bin/bash
# -----------------------------------------------------------------------
# Make fabric's apt repository signing key, once (manual 1.3.1.1, 2.1.1.2, 3.14.1):
# a dedicated Ed25519 signing key that expires in two years, with a random
# passphrase. Both go into this repository's Actions secrets
# (GPG_PRIVATE_KEY, GPG_PASSPHRASE) through `gh secret set` on standard input,
# never a command line. GitHub never gives a secret back, so the folder you
# name gets the offline copy: the private key (still encrypted with its
# passphrase), the passphrase, the revocation certificate and the public key.
# Keep that folder offline (a USB stick, a password manager): with it the key's
# expiry can be extended or the secret restored; without it a lost secret means
# a new key, which every host then fetches again.
#
#   bash scripts/release/make-apt-key.sh <offline folder, e.g. a USB stick>
#
# Run it from Git Bash on the owner's PC, in the repository's folder.
#
# Needs gpg and an authenticated `gh` with admin rights on the repository.
# Run it by hand (the repository's owner): agents do not handle signing keys.
# -----------------------------------------------------------------------
set -euo pipefail
KEEP="${1:?usage: make-apt-key.sh <offline folder, e.g. a USB stick>}"
REPO="${FABRIC_REPO:-archdukejim/fabric-ctl}"
mkdir -p "$KEEP"
export GNUPGHOME
GNUPGHOME="$(mktemp -d)"
trap 'gpgconf --kill gpg-agent 2>/dev/null; rm -rf "$GNUPGHOME"' EXIT
umask 077

PASS="$(head -c 32 /dev/urandom | base64 | tr -d '/+=')"
printf '%s' "$PASS" > "$GNUPGHOME/pass"
gpg --batch --pinentry-mode loopback --passphrase-file "$GNUPGHOME/pass" \
    --quick-generate-key "open-fabric apt repository <apt@open-fabric.invalid>" ed25519 sign 2y
FPR="$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" {print $10; exit}')"

gpg --batch --pinentry-mode loopback --passphrase-file "$GNUPGHOME/pass" --armor \
    --export-secret-keys "$FPR" | gh secret set GPG_PRIVATE_KEY --repo "$REPO"
gh secret set GPG_PASSPHRASE --repo "$REPO" < "$GNUPGHOME/pass"
cp "$GNUPGHOME/openpgp-revocs.d/$FPR.rev" "$KEEP/open-fabric-apt-$FPR.rev"
gpg --batch --armor --export "$FPR" > "$KEEP/open-fabric-apt-public.key"
# the offline copy: the private key encrypted with its passphrase, and the passphrase beside it
gpg --batch --pinentry-mode loopback --passphrase-file "$GNUPGHOME/pass" --armor     --export-secret-keys "$FPR" > "$KEEP/open-fabric-apt-private.key"
cp "$GNUPGHOME/pass" "$KEEP/open-fabric-apt-passphrase.txt"

echo "signing key $FPR stored as GPG_PRIVATE_KEY and GPG_PASSPHRASE in $REPO's Actions secrets"
echo "offline copy in $KEEP (keep this folder offline):"
echo "  open-fabric-apt-private.key + open-fabric-apt-passphrase.txt  the key, to extend its expiry or restore the secret"
echo "  open-fabric-apt-$FPR.rev  the revocation certificate: revokes the key if it leaks"
echo "  open-fabric-apt-public.key  the public key (also published with the repository)"
