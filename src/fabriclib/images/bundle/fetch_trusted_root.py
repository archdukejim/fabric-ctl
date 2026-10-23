import json
import os
import shutil
import tempfile

from fabriclib.common.errors import ValidationError
from fabriclib.images.bundle.cosign_run import cosign_run

TARGET = os.path.join(".sigstore", "root", "tuf-repo-cdn.sigstore.dev", "targets", "trusted_root.json")


def fetch_trusted_root(cosign_image):
    """Purpose: Sigstore's trusted root (the certificate authority's and the transparency log's keys) that an offline
             host checks keyless signatures against, fetched by cosign through Sigstore's TUF repository, which
             cosign verifies from the TUF root it ships with (`cosign initialize`).
    Inputs:  cosign_image — str, the pinned cosign ref.
    Returns: bytes, trusted_root.json.
    Fails:   ValidationError when cosign cannot fetch or verify it (no network to Sigstore) or the file is not JSON.
    Feeds:   scripts/images/trusted_root.py (the trusted root the package ships)."""
    home = tempfile.mkdtemp(prefix="fabric-tuf-")
    try:
        os.chmod(home, 0o777)                    # cosign's image runs as its own non-root user
        res = cosign_run(cosign_image, ["initialize"], home=home, timeout=180)
        path = os.path.join(home, TARGET)
        if res.returncode != 0 or not os.path.exists(path):
            why = (res.stderr or res.stdout or "no output").strip().splitlines()[-1:] or ["no output"]
            raise ValidationError(f"Sigstore's trusted root could not be fetched ({why[0][:300]})")
        with open(path, "rb") as f:
            data = f.read()
        try:
            json.loads(data)
        except ValueError as e:
            raise ValidationError(f"Sigstore's trusted root is not JSON ({e})")
        return data
    finally:
        shutil.rmtree(home, ignore_errors=True)
