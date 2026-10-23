import json
import os
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.images.constants import VERIFIED
from fabriclib.images.remember_verified import remember_verified


def _remembered(cache):
    """Purpose: the digests already verified on this host.
    Inputs:  cache — str, path of the verified-digests file.
    Returns: dict {digest: {"ref", "at"}}; {} when the file is missing or unreadable as JSON.
    Fails:   OSError if the file exists but cannot be read.
    Feeds:   verify_signature."""
    if not os.path.exists(cache):
        return {}
    try:
        with open(cache) as f:
            return json.load(f)
    except ValueError:
        return {}


def verify_signature(ref, cosign_image, signer, issuer, cache=VERIFIED, timeout=300):
    """Purpose: refuse a published image unless it carries a keyless signature by fabric's images workflow
             (decisions 2.1.14.6, 2.1.14.10; manual 1.14.3.4): `cosign verify` from the pinned cosign image (2.1.14.11),
             the certificate's identity matching `signer` and its issuer equal to `issuer`. A digest that verified is
             remembered in `cache`, so it is checked once.
    Inputs:  ref — str, "repo:tag@sha256:…" (pinned by digest); cosign_image — str, the pinned cosign image
             (vars image_cosign); signer — str, regular expression for the certificate identity; issuer — str, the
             OIDC issuer (both from the lock's published section); cache — str, path of the remembered digests
             (root, 0600); timeout — seconds for the check.
    Returns: True (verified now or before).
    Fails:   ValidationError if ref is not pinned by digest, or the check refuses it: no signature, another signer,
             or a check that cannot run (no network to the registry or Sigstore, an air-gapped host) — the image is
             then not used. OSError if the cache cannot be written.
    Feeds:   deploy/verify_published_images; tests/images/verify.sh."""
    if "@sha256:" not in (ref or ""):
        raise ValidationError(f"{ref!r} is not pinned by digest")
    digest = ref.split("@", 1)[1]
    known = _remembered(cache)
    if digest in known:
        return True
    cmd = ["docker", "run", "--rm", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
           "--tmpfs", "/tmp:size=16m", "-e", "HOME=/tmp", cosign_image, "verify",
           "--certificate-identity-regexp", signer, "--certificate-oidc-issuer", issuer, ref]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ValidationError(f"{ref}: the signature check did not finish in {timeout}s (no network?); not used "
                              f"(image_signature_check: false turns the check off, manual 1.14.3.4)")
    if res.returncode != 0:
        why = (res.stderr or res.stdout).strip().splitlines()[-1:] or ["no output"]
        raise ValidationError(f"{ref}: no valid signature by fabric's images workflow ({why[0][:300]}); not used "
                              f"(image_signature_check: false turns the check off, manual 1.14.3.4)")
    remember_verified(cache, [ref])
    return True
