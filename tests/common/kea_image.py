"""The tests' own Kea image (tests/kea/run.py, scan.py, relay.py; tests/samba/ipam_two_site.py): built from fabric's
packaging with the versions the locks pin, as an install builds it."""
import os
import subprocess

from fabriclib.common.read_images_lock import read_images_lock
from fabriclib.common.read_packages_lock import read_packages_lock

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TAG = "fabric/kea:test"


def build_kea_image(tag=TAG, fingerprint=None):
    """Purpose: build Kea's image from packaging/images/kea, Debian and ISC's repository as config/ pins them.
    Inputs:  tag — the image's tag, or None for none (a build expected to fail); fingerprint — the repository key's
             fingerprint to give (default the pinned one; a test of the build's refusal gives another).
    Returns: subprocess.CompletedProcess (text), the build's own exit status and output.
    Fails:   never for a failed build (the caller checks returncode); OSError when Docker is not installed.
    Feeds:   tests/kea/run.py, scan.py, relay.py; tests/samba/ipam_two_site.py."""
    debian = read_images_lock(os.path.join(REPO, "config"))["debian"]["ref"]
    k = read_packages_lock(os.path.join(REPO, "config"))["kea"]
    cmd = ["docker", "build", "-q", *(["-t", tag] if tag else []), "--build-arg", f"BASE_IMAGE={debian}",
           "--build-arg", f"KEA_VERSION={k['version']}", "--build-arg", f"KEA_REPO={k['repo']}",
           "--build-arg", f"KEA_SUITE={k['suite']}", "--build-arg", f"KEA_KEY_URL={k['key_url']}",
           "--build-arg", f"KEA_KEY_FINGERPRINT={fingerprint or k['key_fingerprint']}",
           os.path.join(REPO, "packaging", "images", "kea")]
    return subprocess.run(cmd, capture_output=True, text=True)
