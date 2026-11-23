from agent.read_chunked import read_chunked
from agent.require_domain_admin import require_domain_admin
from fabriclib.backup.is_domain_admin import is_domain_admin
from fabriclib.backup.receive_upload import receive_upload
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.write_audit import write_audit


def _sized(rfile, length, size=1 << 20):
    """Purpose: a body of a known length, as pieces of at most `size` bytes.
    Inputs:  rfile — the request's stream; length — Content-Length; size — the largest piece.
    Returns: a generator of bytes.
    Fails:   ValidationError for a body cut short.
    Feeds:   post_upload."""
    while length > 0:
        piece = rfile.read(min(length, size))
        if not piece:
            raise ValidationError("the upload was cut short")
        length -= len(piece)
        yield piece


def post_upload(user, headers, rfile, load=load_vars, allowed=is_domain_admin, receive=receive_upload,
                audit=write_audit):
    """Purpose: POST /v1/backup/upload (manual 1.3.7.9, 1.3.3.1): a bundle's bytes as they arrive, chunked or of a
             known length, written into the backups folder by receive_upload. A Domain Admin only, checked before a
             byte is read; audited.
    Inputs:  user — the token's user (None: a root peer); headers — the request's (X-Fabric-Bundle: the file's name;
             Transfer-Encoding or Content-Length); rfile — the body; load, allowed, receive, audit — load_vars,
             is_domain_admin, receive_upload, write_audit (tests).
    Returns: {"file", "size"}.
    Fails:   ValidationError: not a Domain Admin, a bad Content-Length, receive_upload's refusals.
    Feeds:   agent/handler (do_POST, before any body is read)."""
    require_domain_admin(load(), user, allowed)
    name = headers.get("X-Fabric-Bundle", "")
    if "chunked" in (headers.get("Transfer-Encoding") or "").lower():
        pieces = read_chunked(rfile)
    else:
        try:
            pieces = _sized(rfile, int(headers.get("Content-Length") or 0))
        except ValueError:
            raise ValidationError("Content-Length is not a number") from None
    out = receive(name, pieces)
    audit(user or "root", "BACKUP_UPLOAD", f"file={out['file']} size={out['size']}", source="web")
    return out
