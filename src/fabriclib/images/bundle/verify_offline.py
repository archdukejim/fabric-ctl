import os
import shutil
import tempfile

from fabriclib.common.errors import ValidationError
from fabriclib.images.bundle.cosign_run import cosign_run

# what `cosign sign` (3.x) signs: an in-toto statement naming the image's digest
SIGN_TYPE = "https://sigstore.dev/cosign/sign/v1"


def verify_offline(ref, index, signature, trusted_root, cosign_image, signer, issuer):
    """Purpose: check a published image's keyless signature with no network (decision 2.1.14.14, 2.3.1.11.8): the
             carried Sigstore bundle must sign the image's own index (whose digest is the one the lock pins), with a
             certificate from Sigstore's authority naming fabric's images workflow (`signer`, `issuer`, 2.1.14.6),
             logged in the transparency log — all proven from the carried trusted root; cosign runs with no network.
    Inputs:  ref — str, the image's "repo:tag@sha256:…" (for messages); index — bytes, the image's index;
             signature — bytes, its Sigstore bundle; trusted_root — bytes, trusted_root.json; cosign_image — the
             pinned cosign ref, already on the host; signer — regular expression for the certificate identity;
             issuer — the OIDC issuer.
    Returns: True.
    Fails:   ValidationError naming the image and cosign's reason: another signer, a statement for another digest,
             a certificate or log proof the trusted root does not vouch for, or cosign not on the host.
    Feeds:   import_bundle."""
    work = tempfile.mkdtemp(prefix="fabric-verify-")
    try:
        for name, data in (("index", index), ("signature.json", signature), ("trusted_root.json", trusted_root)):
            with open(os.path.join(work, name), "wb") as f:
                f.write(data)
        os.chmod(work, 0o755)
        for name in os.listdir(work):
            os.chmod(os.path.join(work, name), 0o644)
        res = cosign_run(cosign_image, ["verify-blob-attestation", "--new-bundle-format",
                                        "--bundle", "/check/signature.json", "--trusted-root",
                                        "/check/trusted_root.json", "--type", SIGN_TYPE,
                                        "--certificate-identity-regexp", signer,
                                        "--certificate-oidc-issuer", issuer, "/check/index"],
                         mounts=[(work, "/check", "ro")], network=False, timeout=120)
        if res.returncode != 0:
            why = (res.stderr or res.stdout or "no output").strip().splitlines()[-1:] or ["no output"]
            raise ValidationError(f"{ref}: its carried signature does not verify ({why[0][:300]})")
        return True
    finally:
        shutil.rmtree(work, ignore_errors=True)
