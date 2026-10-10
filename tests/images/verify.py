"""Signature verification of published images (manual 1.14.3.4, decisions 2.1.14.6, 2.1.14.10, 2.1.14.11), against real keyless
signatures in Sigstore's public log. Needs Docker and network access. Run by tests/images/run.sh.

- a real keyless-signed image (cosign's own release, signed by Sigstore's release identity) verifies with its
  signer, and the verified digest is remembered (root-only file), so it is not checked again
- the same image is refused with fabric's signer: a signature by anyone else does not count
- an unsigned image (the pinned Debian base) is refused; so is one whose registry cannot be reached
- a ref not pinned by digest is refused before anything runs
- the deploy step checks only images in use, and does nothing while image_signature_check is false
"""
import os
import shutil
import stat
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.common.read_published_lock import read_published_lock  # noqa: E402
from fabriclib.deploy.verify_published_images import verify_published_images  # noqa: E402
from fabriclib.images.verify_signature import verify_signature  # noqa: E402

PASS = FAIL = 0
LOCK = read_images_lock(os.path.join(REPO, "config"))
PUBLISHED = read_published_lock(os.path.join(REPO, "config"))
COSIGN = LOCK["cosign"]["ref"]
# cosign's own images are signed keyless by Sigstore's release service account
SIGSTORE = ("^keyless@projectsigstore\\.iam\\.gserviceaccount\\.com$", "https://accounts.google.com")


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {detail}")


def refused(ref, signer, issuer, cache):
    try:
        verify_signature(ref, COSIGN, signer, issuer, cache=cache, timeout=180)
    except ValidationError as e:
        return str(e)
    return ""


work = tempfile.mkdtemp(prefix="fabric-verify-")
try:
    cache = os.path.join(work, "images", "verified.json")
    ok = not refused(COSIGN, *SIGSTORE, cache)
    check("a real keyless signature verifies with its signer (cosign's own image)", ok)
    mode = stat.S_IMODE(os.stat(cache).st_mode) if os.path.exists(cache) else None
    check("the verified digest is remembered, root-only (0600)",
          mode == 0o600 and COSIGN.split("@")[1] in open(cache).read(), oct(mode or 0))
    # remembered: a second check does not run cosign at all (a cosign image that does not exist would fail)
    try:
        again = verify_signature(COSIGN, "fabric-test/no-such-cosign:none", *SIGSTORE, cache=cache)
    except ValidationError:
        again = False
    check("a remembered digest is not checked again", again is True)

    fresh = os.path.join(work, "fresh.json")
    why = refused(COSIGN, PUBLISHED["signer"], PUBLISHED["issuer"], fresh)
    check("the same image is refused with fabric's signer (another signer does not count)",
          "no valid signature" in why and not os.path.exists(fresh), why)
    why = refused(LOCK["debian"]["ref"], PUBLISHED["signer"], PUBLISHED["issuer"], fresh)
    check("an unsigned image (the pinned Debian base) is refused", "no valid signature" in why, why)
    why = refused("localhost:5999/fabric-test/bind9:1@sha256:" + "0" * 64, PUBLISHED["signer"],
                  PUBLISHED["issuer"], fresh)
    check("an image whose registry cannot be reached is refused, not used (2.1.14.10)", "no valid signature" in why, why)
    why = refused("ghcr.io/archdukejim/open-fabric/bind9:1.5.0", PUBLISHED["signer"], PUBLISHED["issuer"], fresh)
    check("a ref not pinned by digest is refused", "not pinned by digest" in why, why)

    # the deploy step: only images this deploy runs, and nothing while the check is off
    render = os.path.join(work, "render")
    os.makedirs(os.path.join(render, "bind9"))
    open(os.path.join(render, "bind9", "docker-compose.yml"), "w").write("services: {}\n")
    paths = {"jinja": os.path.join(REPO, "templates"), "render": render}
    unsigned = LOCK["debian"]["ref"]
    host = {"image_fabric_bind9": unsigned, "image_fabric_stepca": unsigned, "image_cosign": COSIGN,
            "service_users": {"bind": {"uid": 600, "gid": 600}}}
    try:
        verify_published_images(paths, host)
        why = ""
    except ValidationError as e:
        why = str(e)
    # covers: setting:image_fabric_bind9 setting:image_fabric_stepca -
    check("setup stops before installing anything when a published image in use is unsigned",
          "no valid signature" in why, why)
    # covers: setting:image_signature_check +
    check("the check off (image_signature_check: false): nothing is checked",
          verify_published_images(paths, dict(host, image_signature_check=False)) == [])
    os.remove(os.path.join(render, "bind9", "docker-compose.yml"))
    check("an image this host does not run (no rendered compose file) is not checked",
          verify_published_images(paths, host) == [])
finally:
    shutil.rmtree(work, ignore_errors=True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
