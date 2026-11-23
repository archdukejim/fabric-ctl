import hmac
import os
import re
import secrets

# a bundle's name (backup/bundle_name.PATTERN; the listener runs on the standard library alone, manual 1.3.6.3)
NAME = re.compile(r"^fabric-[A-Za-z0-9-]+-\d{8}T\d{6}Z-[a-z]+\.fabric\.tar$")
LIMIT = 8 << 30                     # an upload's largest size (manual 1.3.7.10, as the console's)
RESERVE = 1 << 30                   # what an upload leaves free on the disk


class UploadRefused(Exception):
    """An upload refused: its HTTP status and the words the page shows."""

    def __init__(self, status, why):
        """Purpose: the refusal.
        Inputs:  status — the HTTP status; why — str.
        Returns: None.
        Fails:   never.
        Feeds:   save_upload."""
        super().__init__(why)
        self.status = status


def _free(path):
    """Purpose: the bytes free to this process on a path's disk.
    Inputs:  path — a folder.
    Returns: int.
    Fails:   OSError.
    Feeds:   save_upload."""
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def save_upload(reader, csrf, folder, limit=LIMIT, reserve=RESERVE, free=_free, tick=lambda: None):
    """Purpose: Restore from a backup's upload (manual 1.3.7.10 step 1) streamed to the upload folder as it arrives,
             never held: the CSRF field first, then the question's number, then the file, written to a hidden .part
             (0600) and renamed to its bundle name only once whole. Setup, as root, checks it and copies it out.
    Inputs:  reader — a MultipartReader over the request; csrf — the session's token; folder — the upload folder
             (setup makes it for the bundle's question: the listener's, 0700); limit, reserve — bytes; free — the free
             bytes of a path's disk (tests); tick — called as each piece lands (the person is still here).
    Returns: (seq, path): the question the upload answers and the file's path.
    Fails:   UploadRefused: 403 a stale or missing token; 400 a form not in that order, a name that is not a bundle's,
             one already there, a body cut short; 413 past the limit; 507 the disk too full; 409 no upload folder (the
             bundle is not being asked). The .part file is removed on any refusal.
    Feeds:   listener/request_handler (POST /upload)."""
    try:
        part = reader.next_part()
        if not part or part[0] != "csrf" or not hmac.compare_digest(reader.read_small().encode(), csrf.encode()):
            raise UploadRefused(403, "Refused: this page is out of date (its security token is stale). Open the site "
                                     "again; nothing was changed.")
        part = reader.next_part()
        if not part or part[0] != "seq":
            raise UploadRefused(400, "Refused: the upload's form is not this site's. Nothing was changed.")
        seq = reader.read_small(32)
        part = reader.next_part()
        if not part or part[0] != "bundle" or part[1] is None:
            raise UploadRefused(400, "Refused: no file was chosen. Nothing was changed.")
        name = os.path.basename(part[1])
    except ValueError as exc:
        raise UploadRefused(400, f"Refused: {exc}. Nothing was changed.") from None
    if not NAME.match(name):
        raise UploadRefused(400, "Refused: the file's name is not a bundle's (fabric-<host>-<when>-<kind>.fabric.tar). "
                                 "Keep the name it was downloaded with. Nothing was kept.")
    if not os.path.isdir(folder):
        raise UploadRefused(409, "Refused: setup is not asking for a bundle now. Nothing was kept.")
    final = os.path.join(folder, name)
    if os.path.exists(final):
        raise UploadRefused(400, f"Refused: {name} was already uploaded. Pick it by its path.")
    path, size = os.path.join(folder, f".upload-{secrets.token_hex(8)}.part"), 0
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)   # O_EXCL: never through a link
        with os.fdopen(os.open(path, flags, 0o600), "wb") as f:
            for piece in reader.read_part():
                size += len(piece)
                if size > limit:
                    raise UploadRefused(413, f"Refused: the upload is larger than {limit >> 30} GiB. Copy the bundle "
                                             "to the host instead. Nothing was kept.")
                if free(folder) - len(piece) < reserve:
                    raise UploadRefused(507, f"Refused: the disk would have less than {reserve >> 30} GiB free. Make "
                                             "room first. Nothing was kept.")
                f.write(piece)
                tick()
        os.rename(path, final)
    except ValueError as exc:
        raise UploadRefused(400, f"Refused: {exc}. Nothing was kept.") from None
    finally:
        if os.path.exists(path):
            os.remove(path)
    return seq, final
