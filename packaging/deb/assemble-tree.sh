#!/bin/bash
# -----------------------------------------------------------------------
# Assemble the installed tree from the repository — the one place that
# knows how the repository's layout (manual 1.2.2, global Rule 7) maps
# onto it (the .deb build and the tests that need an installed-looking
# tree both use it):
#
#   src/fabriclib, src/agent, src/federation      -> <dest>/fabric/lib/…
#   src/ux/cli/{deploy.py,interactive.py,keycloak_bootstrap.py,manage.sh}
#                                                 -> <dest>/fabric/lib/
#   src/webui, src/ux/web/{server,devserver}.py   -> <dest>/fabric/lib/webui/
#   templates/webui-app, static/webui-app         -> <dest>/fabric/lib/webui/{templates,static}/
#   templates/* (the service templates)           -> <dest>/fabric/jinja/
#   packaging/images/<service>/                   -> <dest>/fabric/jinja/<service>/build/   (image build contexts)
#   src/containers/freeradius/                    -> <dest>/fabric/jinja/freeradius/python/
#   static/vendor/*.min.js, static/nginx/style.css -> <dest>/fabric/jinja/nginx/www/{manual,shared}/
#   config/{VERSION,images.lock.yaml,link-vars-template.yaml,sigstore-trusted-root.json,apt-repository.yaml}
#                                                 -> <dest>/fabric/
#   docs/, LICENSE, THIRD_PARTY_NOTICES, README.md -> <dest>/
#
# The installed layout (/usr/lib/fabricctl/fabric, /opt/fabric, 2.1.2.5) never
# depends on the repository's: installs upgrade in place. Tracked and
# untracked-but-not-ignored files only: never secrets, local vars or
# __pycache__. Needs git and GNU tar.
#
#   packaging/deb/assemble-tree.sh <dest>
# -----------------------------------------------------------------------
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DEST="${1:?usage: assemble-tree.sh <dest>}"
mkdir -p "$DEST"

# files under the given paths as git sees them (deleted-but-unstaged ones skipped), NUL-separated
# Purpose: list the repository files to ship under the given paths: tracked plus untracked-but-not-ignored,
#          skipping files deleted from the working tree, so secrets, local vars and __pycache__ never ship.
# Inputs:  $@ — paths relative to $REPO (git pathspecs). Reads the git index and working tree of $REPO.
# Returns: NUL-separated repo-relative paths on stdout; status of the subshell pipeline.
# Fails:   non-zero (and set -e/pipefail stops the script) if git fails, e.g. $REPO is not a git checkout.
# Feeds:   copy.
files() {
    (cd "$REPO" && git ls-files -z --cached --others --exclude-standard -- "$@" \
        | while IFS= read -r -d '' f; do [ -e "$f" ] && printf '%s\0' "$f"; done)
}
# Purpose: copy the shipped files under some repository paths into $DEST, renaming them on the way.
# Inputs:  $1 — a GNU tar --transform expression (sed-style, applied to repo-relative paths);
#          $2… — repository paths to copy (as for files). Writes under $DEST.
# Returns: status of the tar pipeline; files land at $DEST/<transformed path>.
# Fails:   non-zero (set -e/pipefail stops the script) if git or tar fails; needs GNU tar (--null -T, --transform).
# Feeds:   the script body (src/, templates/, static/, packaging/images/, config/, docs and top-level files).
copy() {  # copy <tar --transform expression> <paths...>
    local expr="$1"; shift
    files "$@" | (cd "$REPO" && tar --null -T - -cf -) | tar -xf - -C "$DEST" --transform "$expr"
}

copy 's,^src/,fabric/lib/,' src/fabriclib src/agent src/federation
copy 's,^src/ux/cli/,fabric/lib/,' src/ux/cli/deploy.py src/ux/cli/interactive.py src/ux/cli/keycloak_bootstrap.py \
    src/ux/cli/manage.sh
copy 's,^src/webui/,fabric/lib/webui/,' src/webui
copy 's,^src/ux/web/,fabric/lib/webui/,' src/ux/web/server.py src/ux/web/devserver.py
copy 's,^templates/webui-app/,fabric/lib/webui/templates/,;s,^static/webui-app/,fabric/lib/webui/static/,' \
    templates/webui-app static/webui-app
copy 's,^templates/,fabric/jinja/,' templates ':(exclude)templates/webui-app'
for svc in bind9 freeradius kea keycloak samba stepca; do
    copy "s,^packaging/images/$svc/,fabric/jinja/$svc/build/," "packaging/images/$svc"
done
copy 's,^packaging/images/webui/,fabric/jinja/webui/build/,' packaging/images/webui/Dockerfile \
    packaging/images/webui/.dockerignore
copy 's,^src/containers/freeradius/,fabric/jinja/freeradius/python/,' src/containers/freeradius
copy 's,^src/containers/samba/,fabric/jinja/samba/converge/,' src/containers/samba
copy 's,^static/vendor/,fabric/jinja/nginx/www/manual/,;s,^static/nginx/,fabric/jinja/nginx/www/shared/,' \
    static/vendor/marked.min.js static/vendor/mermaid.min.js static/nginx/style.css
copy 's,^config/,fabric/,' config/VERSION config/images.lock.yaml config/link-vars-template.yaml config/sigstore-trusted-root.json \
    config/apt-repository.yaml
copy 's,^,,' docs LICENSE THIRD_PARTY_NOTICES README.md
find "$DEST" -name __pycache__ -prune -exec rm -rf {} +
