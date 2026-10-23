import base64
import json

from fabriclib.common.errors import ValidationError
from fabriclib.images.bundle.cosign_run import cosign_run

BUNDLE_TYPE = "application/vnd.dev.sigstore.bundle"


def fetch_signature(ref, cosign_image):
    """Purpose: the Sigstore bundle of a published image's keyless signature (decision 2.1.14.6), as cosign stores it
             beside the image in the registry: the signing certificate, the transparency log's entry and proof, and
             the signed statement naming the image's digest — everything a host needs to check it offline.
    Inputs:  ref — str, "repo:tag@sha256:…"; cosign_image — str, the pinned cosign ref.
    Returns: bytes, the bundle's JSON.
    Fails:   ValidationError when cosign finds no signature, or what it gives is not a Sigstore bundle for this
             digest (the message names the image).
    Feeds:   export_bundle."""
    digest = ref.split("@", 1)[1]
    res = cosign_run(cosign_image, ["download", "signature", ref])
    lines = [ln for ln in (res.stdout or "").splitlines() if ln.strip().startswith("{")]
    if res.returncode != 0 or not lines:
        why = (res.stderr or res.stdout or "no output").strip().splitlines()[-1][:300]
        raise ValidationError(f"{ref}: no signature to carry ({why})")
    for line in lines:
        try:
            bundle = json.loads(line)
            statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
        except (ValueError, KeyError):
            continue
        subjects = [s.get("digest", {}).get("sha256") for s in statement.get("subject") or []]
        if str(bundle.get("mediaType", "")).startswith(BUNDLE_TYPE) and digest[7:] in subjects:
            return line.strip().encode()
    raise ValidationError(f"{ref}: cosign gave no Sigstore bundle signing this digest")
