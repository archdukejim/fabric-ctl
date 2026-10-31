import http.client
import ssl
import urllib.parse

TIMEOUT = 3          # seconds: a site's console that does not answer in this is shown as down (2.1.8.30)


def console_reachable(url, root_ca, timeout=TIMEOUT):
    """Purpose: whether a site's console answers (decision 2.1.8.30 health (3), manual 1.8.6.12): one HTTPS request
             to it, its certificate verified against fabric's root CA and its name; any HTTP answer below 500 is up
             (a sign-in redirect is an answer). No answer, a certificate that does not verify, or a server error is
             down.
    Inputs:  url — the console's address, "https://<host>[:<port>]"; root_ca — fabric's root CA file; timeout —
             seconds.
    Returns: (up: bool, why: str — "" when up, else what failed).
    Fails:   never.
    Feeds:   federation/site_selector."""
    parts = urllib.parse.urlsplit(url or "")
    if parts.scheme != "https" or not parts.hostname:
        return False, "no console recorded"
    try:
        ctx = ssl.create_default_context(cafile=root_ca)
        conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=ctx, timeout=timeout)
        try:
            conn.request("HEAD", "/")
            status = conn.getresponse().status
        finally:
            conn.close()
    except ssl.SSLCertVerificationError as e:
        return False, f"its certificate did not verify: {e.verify_message}"
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError) as e:
        return False, f"no answer: {e}" if str(e) else "no answer"
    if status >= 500:
        return False, f"it answered {status}"
    return True, ""
