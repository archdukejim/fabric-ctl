import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request

from fabriclib.common.errors import ValidationError

# the manifest types an image's index and platform manifests come as (OCI and Docker's own)
MANIFEST_TYPES = ", ".join([
    "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"])
CHUNK = 1 << 20
_TOKENS = {}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Purpose: let a registry's redirect come back to the caller instead of being followed with its token.
        Inputs:  urllib's redirect arguments (unused).
        Returns: None (urllib then raises the 3xx as an HTTPError).
        Fails:   never.
        Feeds:   _open (a blob stored elsewhere is fetched from there without the registry's token)."""
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _token(challenge):
    """Purpose: an anonymous pull token from the realm a registry's 401 names (Docker's token protocol).
    Inputs:  challenge — str, the WWW-Authenticate header: Bearer realm="…",service="…",scope="…".
    Returns: str token.
    Fails:   ValidationError when the challenge is not a Bearer one or the realm gives no token;
             urllib.error.URLError when the realm cannot be reached.
    Feeds:   _open."""
    if not challenge.lower().startswith("bearer "):
        kind = challenge.split(' ')[0] or 'no'
        raise ValidationError(f"the registry asks for {kind} sign-in: fabric's images pull without one")
    fields = dict(part.split("=", 1) for part in challenge[7:].replace('"', "").split(","))
    realm = fields.pop("realm")
    if realm in _TOKENS and _TOKENS[realm][0] == fields:
        return _TOKENS[realm][1]
    with urllib.request.urlopen(f"{realm}?{urllib.parse.urlencode(fields)}", timeout=60) as r:
        body = json.load(r)
    token = body.get("token") or body.get("access_token")
    if not token:
        raise ValidationError(f"{realm} gave no pull token")
    _TOKENS[realm] = (fields, token)
    return token


def _open(url, accept):
    """Purpose: GET a registry URL, signing in anonymously when asked and following a redirect without the token.
    Inputs:  url — str; accept — str Accept header or None.
    Returns: an open http.client.HTTPResponse (200).
    Fails:   ValidationError for any other answer (the URL and the status); urllib.error.URLError when the
             registry cannot be reached.
    Feeds:   fetch_blob."""
    headers = {"Accept": accept} if accept else {}
    for _ in range(2):
        try:
            return _OPENER.open(urllib.request.Request(url, headers=headers), timeout=120)
        except urllib.error.HTTPError as e:
            if e.code == 401 and "Authorization" not in headers:
                headers["Authorization"] = f"Bearer {_token(e.headers.get('WWW-Authenticate', ''))}"
                continue
            if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                where = urllib.parse.urljoin(url, e.headers["Location"])
                return urllib.request.urlopen(urllib.request.Request(where), timeout=120)
            raise ValidationError(f"{url}: the registry answered {e.code} {e.reason}")
    raise ValidationError(f"{url}: refused after signing in")


def fetch_blob(host, path, digest, sink=None, manifest=False):
    """Purpose: one blob or manifest of an image, by digest, from its registry, checked against that digest as it
             arrives (a registry or a network that changes a byte is caught here, decision 2.1.14.4).
    Inputs:  host, path — from registry_name; digest — "sha256:<hex>"; sink — a binary file to write to as the data
             arrives, or None to return the bytes; manifest — True for /manifests/ (with the manifest Accept types),
             False for /blobs/.
    Returns: (bytes or None, size int, media type str from the answer's Content-Type).
    Fails:   ValidationError when the registry refuses, the digest is not sha256, or what arrived does not hash to
             `digest` (the sink then holds bad data: the caller discards it); urllib.error.URLError and OSError.
    Feeds:   fetch_image."""
    if not digest.startswith("sha256:"):
        raise ValidationError(f"{digest}: only sha256 digests are pinned")
    kind = "manifests" if manifest else "blobs"
    url = f"https://{host}/v2/{path}/{kind}/{digest}"
    h, size, kept = hashlib.sha256(), 0, []
    with _open(url, MANIFEST_TYPES if manifest else None) as r:
        mediatype = (r.headers.get("Content-Type") or "").split(";")[0]
        while True:
            chunk = r.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
            (sink.write(chunk) if sink else kept.append(chunk))
    if f"sha256:{h.hexdigest()}" != digest:
        raise ValidationError(f"{path}@{digest}: what the registry sent does not match its digest")
    return (None if sink else b"".join(kept)), size, mediatype
