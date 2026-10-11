import json
import os
import time
import urllib.request

from fabriclib.common.ensure_dir import ensure_dir
from fabriclib.common.service_user import service_user
from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.dns_filter.common.adguard_paths import adguard_paths
from fabriclib.dns_filter.common.list_id import list_id

MAX_DOWNLOAD = 64 * 1024 * 1024        # the largest list in AdGuard's catalogue is about 25 MB
KB_PER_RULE = 0.14                     # AdGuard Home's steady size per rule, measured on the test Pi (1.12.3.9)


def _fetch(url, timeout):
    """Purpose: download a list over HTTP(S).
    Inputs:  url — str (http or https); timeout — seconds.
    Returns: the text (decoded as UTF-8, bad bytes replaced).
    Fails:   ValueError for another scheme or a list over MAX_DOWNLOAD; urllib.error.URLError, OSError, TimeoutError
             from the download.
    Feeds:   update_lists."""
    if not url.startswith(("https://", "http://")):
        raise ValueError("only http and https lists can be fetched")
    req = urllib.request.Request(url, headers={"User-Agent": "fabric-dns-filter"})
    with urllib.request.urlopen(req, timeout=timeout) as r:      # noqa: S310 (the scheme is checked above)
        data = r.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError(f"larger than {MAX_DOWNLOAD // (1024 * 1024)} MB")
    return data.decode("utf-8", errors="replace")


def _rules(text):
    """Purpose: how many rules a list holds, as AdGuard Home counts them near enough: its lines that are not empty and
             not a comment (`!` or `#`).
    Inputs:  text — the list.
    Returns: int.
    Fails:   never.
    Feeds:   update_lists."""
    return sum(1 for line in text.splitlines() if line.strip() and not line.lstrip().startswith(("!", "#")))


def update_lists(v, catalogue=(), only_missing=False, timeout=120):
    """Purpose: fabric's local copies of the lists (manual 1.12.3.5): every list of the site (ticked or not) and every
             list of AdGuard's catalogue, each downloaded into <base>/dnsfilter/lists/<id>.txt, which AdGuard Home
             reads as a file, so ticking one needs no download. A copy replaces the last only when the download is
             within its size limit, holds at least one rule and not less than half the last copy's rules (a truncated
             download never empties a list); a list that fails keeps its last good copy. Each list's state is kept.
    Inputs:  v — rendered vars (dns_filter_lists, deploy_base_dir, service_users.adguard); catalogue — AdGuard's
             catalogue's lists ([{name, url}], fetch_catalogue), fetched too; only_missing — True to fetch only the
             lists with no copy yet (an apply); timeout — seconds per download. Copies and states of lists no
             longer wanted are removed only by a full run with the catalogue.
    Returns: {"changed": [ids written], "failed": [names that failed this time], "lists": {id: state}} — state: {name,
             url, last_fetch, last_success, rules, memory_mb, error}.
    Fails:   OSError writing the lists folder or the state file. A list's own failure is its state, never raised.
    Feeds:   dns_filter/refresh_lists (`fabricctl dns-filter lists`, the daily timer), dns_filter/deploy_resolver
             (only_missing: a list added by hand in vars.yaml); tests/resolver/run.py."""
    paths = adguard_paths(v)
    _, gid = service_user(v, "adguard")
    ensure_dir(paths["root"], 0o750, 0, gid)
    ensure_dir(paths["lists"], 0o750, 0, gid)
    try:
        with open(paths["state"]) as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    wanted = {}
    for item in [*(v.get("dns_filter_lists") or []), *catalogue]:
        url = str((item or {}).get("url") or "").strip()
        if url.startswith(("https://", "http://")):
            wanted.setdefault(list_id(url), {"name": item.get("name") or url, "url": url})
    result = {"changed": [], "failed": [], "lists": {}}
    for lid, item in wanted.items():
        st = {**state.get(lid, {}), "name": item["name"], "url": item["url"]}
        path = os.path.join(paths["lists"], f"{lid}.txt")
        if only_missing and os.path.exists(path):
            result["lists"][lid] = st
            continue
        st["last_fetch"] = int(time.time())
        try:
            text = _fetch(item["url"], timeout)
            rules = _rules(text)
            if rules == 0:
                raise ValueError("it holds no rules")
            if os.path.exists(path) and rules < (st.get("rules") or 0) / 2:
                raise ValueError(f"{rules} rules, less than half the last copy's {st['rules']}: kept the last copy")
            if write_file_if_changed(path, text, 0o640, 0, gid):
                result["changed"].append(lid)
            st.update({"last_success": st["last_fetch"], "rules": rules,
                       "memory_mb": round(rules * KB_PER_RULE / 1024, 1), "error": None})
        except Exception as e:                  # noqa: BLE001 — a list's failure is its state, never the job's
            st["error"] = f"{type(e).__name__}: {e}"
            result["failed"].append(st["name"])
        result["lists"][lid] = st
    if only_missing or not catalogue:
        keep = {**state, **result["lists"]}     # a partial run: the other lists' copies and states stay
    else:
        keep = result["lists"]
        # a list neither on the site nor in the catalogue any more: its copy and its state go
        for f in os.listdir(paths["lists"]):
            if f.endswith(".txt") and f[:-4] not in wanted:
                os.remove(os.path.join(paths["lists"], f))
    write_file_if_changed(paths["state"], json.dumps(keep, indent=1, sort_keys=True) + "\n", 0o640, 0, gid)
    return result
