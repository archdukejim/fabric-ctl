import os

from fabriclib.common.console import info, ok
from fabriclib.common.errors import ValidationError
from fabriclib.common.lock_dir import lock_dir
from fabriclib.images.bundle.describe_import import describe_import
from fabriclib.images.bundle.import_bundle import import_bundle
from fabriclib.setup.errors import SetupError


def run(ctx):
    """Purpose: setup step `bundle`: with `--offline <bundle>`, check the offline bundle (version, architecture,
             digests, hashes, signatures; decision 2.1.14.14, manual 1.14.4) and load its images, after Docker is
             there and before the deploy, so nothing that follows downloads an image.
    Inputs:  ctx — SetupContext: bundle (the path, or None), source_dir (the package's lock and VERSION), vars
             (image_signature_check).
    Returns: None; the bundle's images in Docker and their verified digests remembered. Without a bundle nothing
             is done. Idempotent: images already present are not loaded again.
    Fails:   SetupError with import_bundle's reason (a bundle for another version or architecture, an image missing
             or not the pinned one, a damaged file, a signature that does not verify, not enough space, Docker's
             classic image store); nothing is loaded unless that reason says so.
    Feeds:   setup step `bundle`, run by run_setup via STEPS."""
    if not ctx.bundle:
        ok("no offline bundle (only with setup --offline <bundle>)")
        return
    info(f"checking the offline bundle {ctx.bundle}")
    try:
        done = import_bundle(ctx.bundle, lock_dir(os.path.join(ctx.source_dir, "jinja")),
                             signature_check=ctx.vars.get("image_signature_check", True), log=info)
    except ValidationError as e:
        raise SetupError(f"offline bundle refused: {e}")
    for line in describe_import(done):
        ok(line)
