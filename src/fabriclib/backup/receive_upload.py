import os
import secrets
import shutil

from fabriclib.backup.bundle_name import PATTERN
from fabriclib.backup.check_bundle import check_bundle
from fabriclib.backup.make_bundle import FOLDER
from fabriclib.common.errors import ValidationError

LIMIT = 8 << 30                     # an upload's largest size (manual 1.3.7.9, 1.3.7.10)
RESERVE = 1 << 30                   # what an upload leaves free on the backups folder's disk


def receive_upload(name, pieces, folder=FOLDER, limit=LIMIT, reserve=RESERVE, check=check_bundle,
                   free=lambda p: shutil.disk_usage(p).free):
    """Purpose: an uploaded bundle written into the backups folder (manual 1.3.7.9): to a hidden .part file (0600) as
             it arrives, stopped past `limit` or when less than `reserve` would be left free, then checked whole and
             renamed to its name, so the list never shows a partial or damaged upload.
    Inputs:  name — the file name it is to have; pieces — iterable of bytes; folder — the backups folder; limit,
             reserve — bytes; check — check_bundle; free — the free bytes of a path's disk (tests).
    Returns: {"file": name, "size": bytes}.
    Fails:   ValidationError (the .part file removed): a name that is not a bundle's, one already in the folder, too
             large, the disk too full, not a whole bundle (check_bundle's words), the body cut short; OSError.
    Feeds:   agent/handler (POST /v1/backup/upload)."""
    if not isinstance(name, str) or not PATTERN.match(name):
        raise ValidationError("the file's name is not a bundle's (fabric-<host>-<when>-<kind>.fabric.tar): keep the "
                              "name it was downloaded with")
    final = os.path.join(folder, name)
    if os.path.exists(final):
        raise ValidationError(f"{name} is already in the backups folder")
    os.makedirs(folder, mode=0o700, exist_ok=True)
    part = os.path.join(folder, f".upload-{secrets.token_hex(8)}.part")
    size = 0
    try:
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            for piece in pieces:
                size += len(piece)
                if size > limit:
                    raise ValidationError(f"the upload is larger than {limit >> 30} GiB")
                if free(folder) - len(piece) < reserve:
                    raise ValidationError(f"the backups folder's disk would have less than {reserve >> 30} GiB free: "
                                          "make room first")
                f.write(piece)
        check(part)
        if os.path.exists(final):
            raise ValidationError(f"{name} is already in the backups folder")
        os.rename(part, final)
    finally:
        if os.path.exists(part):
            os.remove(part)
    return {"file": name, "size": size}
