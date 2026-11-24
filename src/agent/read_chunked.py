from fabriclib.common.errors import ValidationError


def read_chunked(rfile, size=1 << 20):
    """Purpose: a request body sent with Transfer-Encoding: chunked, as pieces of at most `size` bytes (manual 1.3.7.9:
             an upload passed on as it arrives, its length unknown at the start).
    Inputs:  rfile — the request's stream, at the body's first chunk; size — the largest piece yielded.
    Returns: a generator of bytes.
    Fails:   ValidationError for a chunk size that is not hexadecimal or a body cut short.
    Feeds:   agent/handler (POST /v1/backup/upload)."""
    while True:
        line = rfile.readline(1024)
        try:
            left = int(line.split(b";")[0].strip() or b"x", 16)
        except ValueError:
            raise ValidationError("the upload is not in chunks") from None
        if left == 0:
            while rfile.readline(1024) not in (b"\r\n", b"\n", b""):     # trailers, none expected
                pass
            return
        while left:
            piece = rfile.read(min(left, size))
            if not piece:
                raise ValidationError("the upload was cut short")
            left -= len(piece)
            yield piece
        rfile.readline(16)                                              # the chunk's own CRLF
