import base64
import json
import urllib.error
import urllib.request

from fabriclib.common.errors import ValidationError

USER = "fabric-agent"
PORT = 3000


def adguard_api(v, password, method, path, body=None, timeout=30):
    """Purpose: one call to AdGuard Home's HTTP API (manual 1.12.3.4), on fabric_net at ip_adguard, with fabric-agent's
             account: the only way fabric changes AdGuard while it runs.
    Inputs:  v — fabric vars (ip_adguard); password — adguard_api_password (from fabric's secrets, never logged);
             method — "GET" or "POST" (or "PUT"); path — e.g. "/control/filtering/status"; body — a JSON-able value
             or None; timeout — seconds (a list being compiled can take some).
    Returns: the parsed JSON answer, its text when it is not JSON, or None when it is empty.
    Fails:   ValidationError "AdGuard Home is not answering: …" when it cannot be reached (stopped, restarting);
             ValidationError "AdGuard Home refused …: <its message>" for an HTTP error.
    Feeds:   dns_filter/sync_adguard, deploy_adguard, ingest_dns_log (check_host), update_lists (refresh)."""
    req = urllib.request.Request(f"http://{v['ip_adguard']}:{PORT}{path}", method=method,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Basic " + base64.b64encode(
                                              f"{USER}:{password}".encode()).decode()})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:       # noqa: S310 (a fixed http URL on fabric_net)
            text = r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise ValidationError(f"AdGuard Home refused {method} {path}: "
                              f"{e.code} {e.read().decode('utf-8', errors='replace').strip()[:300]}") from None
    except (urllib.error.URLError, OSError) as e:
        raise ValidationError(f"AdGuard Home is not answering: {getattr(e, 'reason', e)}") from None
    if not text.strip():
        return None
    try:
        return json.loads(text)
    except ValueError:
        return text.strip()
