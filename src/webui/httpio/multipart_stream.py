import re

from webui.agentclient.errors import ValidationError

HEADERS_MAX = 8192


class MultipartStream:
    """Purpose: a multipart/form-data body read part by part as it arrives, a part's data yielded in pieces instead of
             held (manual 1.3.7.9: a bundle's upload of up to 8 GiB, past read_form's 64 KiB). Parts come in the
             form's order, so the CSRF field is read and checked before any of the file.
    Feeds:   webui/handler (POST /settings/backups/upload), routes/backups_upload."""

    def __init__(self, rfile, length, content_type, size=1 << 20):
        """Purpose: a reader over one request's body.
        Inputs:  rfile — the request's stream; length — Content-Length; content_type — the request's Content-Type
                 (its boundary); size — the largest piece read and yielded.
        Returns: None.
        Fails:   ValidationError when the body is not multipart/form-data with a boundary.
        Feeds:   webui/handler."""
        m = re.search(r'boundary="?([^";]+)"?', content_type or "")
        if not (content_type or "").startswith("multipart/form-data") or not m:
            raise ValidationError("the upload is not a form with a file")
        self.rfile, self.left, self.size = rfile, max(0, int(length)), size
        self.delim = b"\r\n--" + m.group(1).encode()
        self.buf = b"\r\n"                    # so the first boundary, at the very start, matches as the others do
        self.done = False

    def _fill(self):
        """Purpose: read the next piece of the body into the buffer.
        Inputs:  none.
        Returns: the number of bytes read (0 at the body's end).
        Fails:   OSError from the stream.
        Feeds:   next_part, read_part."""
        if self.left <= 0:
            return 0
        piece = self.rfile.read(min(self.left, self.size))
        self.left -= len(piece)
        self.buf += piece
        return len(piece)

    def next_part(self):
        """Purpose: the next part's name and file name, the reader then at its data.
        Inputs:  none.
        Returns: (name, filename or None), or None after the last part.
        Fails:   ValidationError for a body cut short or headers past 8 KiB.
        Feeds:   webui/handler, routes/backups_upload."""
        while self.delim not in self.buf:
            if not self._fill():
                raise ValidationError("the upload was cut short")
            if self.delim not in self.buf:     # a preamble, or data a part's reader left: keep what may start one
                self.buf = self.buf[-(len(self.delim) - 1):]
        self.buf = self.buf[self.buf.index(self.delim) + len(self.delim):]
        while len(self.buf) < 2 and self._fill():
            pass
        if self.buf[:2] == b"--":
            self.done = True
            return None
        while b"\r\n\r\n" not in self.buf:
            if len(self.buf) > HEADERS_MAX or not self._fill():
                raise ValidationError("the upload's form is not readable")
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        disposition = next((line for line in head.decode(errors="replace").split("\r\n")
                            if line.lower().startswith("content-disposition:")), "")
        name = re.search(r'\bname="([^"]*)"', disposition)
        filename = re.search(r'\bfilename="([^"]*)"', disposition)
        return (name.group(1) if name else ""), (filename.group(1) if filename else None)

    def read_part(self):
        """Purpose: the current part's data, in pieces, up to the next boundary (left for next_part).
        Inputs:  none.
        Returns: a generator of bytes.
        Fails:   ValidationError for a body cut short.
        Feeds:   routes/backups_upload, read_small."""
        keep = len(self.delim) - 1
        while True:
            at = self.buf.find(self.delim)
            if at >= 0:
                if at:
                    yield self.buf[:at]
                self.buf = self.buf[at:]
                return
            if len(self.buf) > keep:
                yield self.buf[:-keep]
                self.buf = self.buf[-keep:]
            if not self._fill():
                raise ValidationError("the upload was cut short")

    def read_small(self, limit=1024):
        """Purpose: a small text part whole (the CSRF field).
        Inputs:  limit — its largest size in bytes.
        Returns: str.
        Fails:   ValidationError past the limit or cut short.
        Feeds:   webui/handler."""
        out = b""
        for piece in self.read_part():
            out += piece
            if len(out) > limit:
                raise ValidationError("a form field is too long")
        return out.decode(errors="replace")
