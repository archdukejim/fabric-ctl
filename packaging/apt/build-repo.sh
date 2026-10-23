#!/bin/bash
# -----------------------------------------------------------------------
# Build fabric's signed apt repository (manual 1.3.1.1, 2.1.1.2) with reprepro:
# suite `stable` from the released packages, suite `testing` from a release
# candidate's, signed with the repository key. Only the published tree is
# written to <out>: dists/, pool/ and public.key (reprepro's conf/ and db/
# stay in a temporary folder).
#
#   GPG_PRIVATE_KEY=<armored key> GPG_PASSPHRASE=<its passphrase> \
#     packaging/apt/build-repo.sh <out> <stable-debs-dir> [<testing-debs-dir>]
#
# The key comes from the environment (Actions secrets), never a command line.
# -----------------------------------------------------------------------
set -euo pipefail
OUT="${1:?usage: build-repo.sh <out> <stable-debs-dir> [<testing-debs-dir>]}"
STABLE="${2:?the folder of the released .deb files}"
TESTING="${3:-}"
: "${GPG_PRIVATE_KEY:?the signing key of the repository, armored}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# the key in a throwaway keyring; its passphrase given to gpg-agent once, so reprepro signs without asking
export GNUPGHOME="$WORK/gnupg"
mkdir -m 0700 "$GNUPGHOME"
echo "allow-preset-passphrase" > "$GNUPGHOME/gpg-agent.conf"
printf '%s\n' "$GPG_PRIVATE_KEY" | gpg --batch --quiet --import
if [ -n "${GPG_PASSPHRASE:-}" ]; then
    for grip in $(gpg --batch --with-colons --with-keygrip --list-secret-keys | awk -F: '$1 == "grp" {print $10}'); do
        printf '%s' "$GPG_PASSPHRASE" | /usr/lib/gnupg/gpg-preset-passphrase --preset "$grip"
    done
fi

mkdir -p "$WORK/repo/conf"
cp "$HERE/distributions" "$WORK/repo/conf/distributions"
shopt -s nullglob
for deb in "$STABLE"/*.deb; do
    reprepro -b "$WORK/repo" includedeb stable "$deb"
done
if [ -n "$TESTING" ]; then
    for deb in "$TESTING"/*.deb; do
        reprepro -b "$WORK/repo" includedeb testing "$deb"
    done
fi
reprepro -b "$WORK/repo" export          # a suite with no package still gets signed indexes

rm -rf "$OUT"
mkdir -p "$OUT"
cp -a "$WORK/repo/dists" "$WORK/repo/pool" "$OUT/" 2>/dev/null || cp -a "$WORK/repo/dists" "$OUT/"
gpg --batch --armor --export > "$OUT/public.key"
touch "$OUT/.nojekyll"                    # GitHub Pages serves the tree as it is
# the site's own page: how to add the repository, and the key's fingerprint to check it against
FPR="$(gpg --batch --with-colons --list-keys | awk -F: '$1 == "fpr" {print $10; exit}')"
URL="${APT_URL:-https://archdukejim.github.io/fabric-ctl}"
cat > "$OUT/index.html" <<EOF
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>fabric apt repository</title>
<style>body{font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;line-height:1.5}
pre{background:#f4f4f4;padding:.8rem;overflow-x:auto}code{font-size:.9rem}</style></head>
<body>
<h1>fabric apt repository</h1>
<p>Signed packages of <code>fabricctl</code>, for Ubuntu 24.04 and 26.04 (amd64 and arm64). Suite <code>stable</code>
holds the releases; <code>testing</code> a release candidate.</p>
<pre><code>wget -qO- $URL/public.key | sudo gpg --dearmor -o /usr/share/keyrings/fabric-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/fabric-archive-keyring.gpg] $URL stable main" | sudo tee /etc/apt/sources.list.d/fabric.list
sudo apt update &amp;&amp; sudo apt install fabricctl
sudo fabricctl setup</code></pre>
<p>Signing key fingerprint: <code>$FPR</code></p>
<p>Source and manual: <a href="https://github.com/archdukejim/fabric-ctl">github.com/archdukejim/fabric-ctl</a></p>
</body></html>
EOF
echo "$OUT"
