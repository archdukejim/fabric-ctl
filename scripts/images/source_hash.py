#!/usr/bin/env python3
"""The source hash of each of fabric's own images (decision 2.1.14.13): what its published image was built from — its
staged build context (packaging/images/stage-contexts.sh: exactly what CI builds) and the pinned base it builds on
(and Kea's pinned packages). The lock records it when an image is pinned; a change to an image's sources without the
image marked `pending` (to be built and published again) is refused, so a stale published image cannot ship.

    python3 scripts/images/source_hash.py            print each image's hash
    python3 scripts/images/source_hash.py --check    exit 1 when a published image's sources changed and it is not
                                                     marked pending (the images suite and CI run this)
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOCK = os.path.join(REPO, "config", "images.lock.yaml")
BASES = {"bind9": ["debian"], "freeradius": ["debian"], "kea": ["debian"],
         "keycloak": ["keycloak"], "samba": ["debian"], "stepca": ["stepca", "golang"], "webui": ["debian"]}
SKIP = ("__pycache__", ".pyc")


def _tree_hash(folder):
    """Purpose: a hash of a folder's files: relative path and content, in path order.
    Inputs:  folder — path.
    Returns: hex sha256.
    Fails:   OSError reading a file.
    Feeds:   source_hashes."""
    h = hashlib.sha256()
    for root, dirs, files in os.walk(folder):
        dirs[:] = sorted(d for d in dirs if d not in SKIP)
        for name in sorted(files):
            if name.endswith(SKIP):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, folder).replace(os.sep, "/")
            h.update(rel.encode() + b"\0")     # not the mode: a Windows-mounted checkout shows every file executable
            with open(path, "rb") as f:
                h.update(hashlib.sha256(f.read()).digest())
    return h.hexdigest()


def source_hashes(repo=REPO):
    """Purpose: every fabric image's source hash, from a checkout.
    Inputs:  repo — the checkout's root.
    Returns: {image: "sha256:<hex>"}.
    Fails:   subprocess.CalledProcessError when staging the contexts fails; OSError; yaml errors reading the lock.
    Feeds:   check, pin_published, this script."""
    lock = yaml.safe_load(open(os.path.join(repo, "config", "images.lock.yaml")))
    out = {}
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, "contexts")
        subprocess.run(["bash", os.path.join(repo, "packaging", "images", "stage-contexts.sh"), dest], check=True,
                       capture_output=True)
        for image, bases in BASES.items():
            pins = {b: (lock["images"][b] or {}).get("digest") or (lock["images"][b] or {}).get("tag") for b in bases}
            if image == "kea":
                pins["packages"] = (lock.get("packages") or {}).get("kea")
            extra = hashlib.sha256(json.dumps(pins, sort_keys=True).encode()).hexdigest()
            out[image] = "sha256:" + hashlib.sha256(
                (_tree_hash(os.path.join(dest, image)) + extra).encode()).hexdigest()
    return out


def check(repo=REPO):
    """Purpose: the published images whose sources changed since they were pinned and are not marked pending.
    Inputs:  repo — the checkout's root.
    Returns: list of str problems ([] when every published image matches its sources or is pending).
    Fails:   as source_hashes.
    Feeds:   this script (--check), tests/images/published.py."""
    published = (yaml.safe_load(open(os.path.join(repo, "config", "images.lock.yaml"))).get("published") or {})
    now = source_hashes(repo)
    out = []
    for image, entry in sorted((published.get("images") or {}).items()):
        if entry.get("pending") or not entry.get("digest"):
            continue
        if not entry.get("source"):
            out.append(f"{image}: the lock records no source hash for its published image (pin it again)")
        elif entry["source"] != now.get(image):
            out.append(f"{image}: its sources changed since {entry.get('tag')} was published: mark it pending (it is "
                       "built and published again with the next release candidate) or publish it")
    return out


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        problems = check()
        print("\n".join(problems) or "every published image matches its sources (or is marked pending)")
        sys.exit(1 if problems else 0)
    if sys.argv[1:]:
        sys.exit(__doc__)
    for name, value in source_hashes().items():
        print(f"{name:<11} {value}")
