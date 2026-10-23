#!/usr/bin/env python3
"""Sigstore's trusted root, shipped in the package (config/sigstore-trusted-root.json; owner 2026-10-22, manual
1.14.4.6): what an offline host checks the keyless signatures of fabric's published images against. Fetched through
the pinned cosign's TUF client, which verifies it from the TUF root cosign ships with. Changed only by a reviewed
commit, like the cosign pin itself; refresh it when Sigstore rotates a key (its announcements) or when `--check` says
it differs.

    python3 scripts/images/trusted_root.py           write config/sigstore-trusted-root.json
    python3 scripts/images/trusted_root.py --check   exit 1 when the shipped file differs from Sigstore's current one
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.images.bundle.fetch_trusted_root import fetch_trusted_root  # noqa: E402

TARGET = os.path.join(REPO, "config", "sigstore-trusted-root.json")


def main(argv):
    """Purpose: write or check the shipped trusted root.
    Inputs:  argv — [] to write, ["--check"] to compare.
    Returns: exit status: 0 written or current, 1 differs (--check), 2 usage.
    Fails:   ValidationError from fetch_trusted_root (no network to Sigstore); OSError.
    Feeds:   this file's __main__."""
    if argv not in ([], ["--check"]):
        print(__doc__, file=sys.stderr)
        return 2
    data = fetch_trusted_root(read_images_lock(os.path.join(REPO, "config"))["cosign"]["ref"])
    if argv == ["--check"]:
        same = os.path.exists(TARGET) and open(TARGET, "rb").read() == data
        print("current" if same else f"{TARGET} differs from Sigstore's current trusted root: run without --check")
        return 0 if same else 1
    with open(TARGET, "wb") as f:
        f.write(data)
    print(f"wrote {TARGET}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
