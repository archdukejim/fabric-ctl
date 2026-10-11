import json
import os
import subprocess
import time
import urllib.request

from fabriclib.common.ensure_dir import ensure_dir
from fabriclib.common.service_user import service_user
from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.dns_filter.common.all_lists import all_lists
from fabriclib.dns_filter.common.list_zone import list_zone
from fabriclib.dns_filter.common.resolver_paths import resolver_paths
from fabriclib.dns_filter.common.resolver_rndc import resolver_rndc
from fabriclib.dns_filter.convert_list import convert_list

MAX_DOWNLOAD = 64 * 1024 * 1024        # the largest list in AdGuard's catalogue is about 25 MB
MAX_RECORDS = 2_000_000                # about 1 GB in BIND (2.3.12.1.17): never a usable list on fabric's hosts
KB_PER_RECORD = 0.53                   # measured on amd64 and arm64 (2.3.12.1.16, 2.3.12.1.17)


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


CHECK_MEMORY = "512m"   # the list check's own memory: a large list takes ~100 MB to check (2.3.1.13 finding 7)


def _check_zone(zone, text):
    """Purpose: named-checkzone on a converted list, in a container of its own made from the authoritative BIND's image
             (it has the tools): never inside BIND's running container, whose memory limit the check would share
             (a large list's check got BIND itself killed, 2.3.1.13 finding 7); no network, no capabilities, a
             read-only root, its own memory. Skipped when the BIND container does not exist (no image to use).
    Inputs:  zone — the zone name; text — the zone file.
    Returns: None when the zone loads (or the check could not run); else the checker's last line (str).
    Fails:   never raises.
    Feeds:   update_lists."""
    try:
        image = subprocess.run(["docker", "inspect", "-f", "{{.Config.Image}}", "bind9"], capture_output=True,
                               text=True, timeout=30)
        if image.returncode != 0 or not image.stdout.strip():
            return None
        r = subprocess.run(["docker", "run", "--rm", "-i", "--network", "none", "--memory", CHECK_MEMORY,
                            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                            "--user", "65534:65534", "--entrypoint", "named-checkzone", image.stdout.strip(),
                            "-q", zone, "/dev/stdin"],
                           input=text, capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode == 0:
        return None
    return (r.stdout + r.stderr).strip().splitlines()[-1] if (r.stdout + r.stderr).strip() else "named-checkzone failed"


def update_lists(v, only_missing=False, reload=True, timeout=120):
    """Purpose: the DNS filter's lists (manual 1.12.2.6): fetch each list (everyone's and each group's, all_lists),
             convert it to a response policy zone, check it, write it when it changed and reload only that zone in the
             resolver; record each list's state. A list that fails keeps its last good copy.
    Inputs:  v — rendered vars (dns_filter_lists, dns_filter_groups, deploy_base_dir, service_users.resolver);
             only_missing — True to
             fetch only the lists with no converted copy yet (an apply); reload — False to leave the resolver alone
             (an apply reconfigures it afterwards); timeout — seconds per download.
    Returns: {"changed": [zones written], "failed": [list names that failed this time], "lists": {zone: state}} —
             state: {name, url, last_fetch, last_success, rules, records, skipped, skipped_by_reason, memory_mb,
             error, reloaded}.
    Fails:   OSError writing the lists folder or the state file. A list's own failure (download, conversion, check)
             is recorded in its state, never raised.
    Feeds:   dns_filter/deploy_resolver (only_missing), dns_filter/run_dns_filter_command (`fabricctl dns-filter
             lists`, the timer's --scheduled run); tests/resolver/run.py."""
    paths = resolver_paths(v)
    _, gid = service_user(v, "resolver")
    ensure_dir(paths["root"], 0o750, 0, gid)
    ensure_dir(paths["lists"], 0o750, 0, gid)
    try:
        with open(paths["state"]) as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    wanted = {list_zone(item["url"]): item for item in all_lists(v)}
    result = {"changed": [], "failed": [], "lists": {}}
    for zone, item in wanted.items():
        st = {**state.get(zone, {}), "name": item.get("name") or item["url"], "url": item["url"]}
        path = os.path.join(paths["lists"], zone)
        if only_missing and os.path.exists(path):
            result["lists"][zone] = st
            continue
        st["last_fetch"] = int(time.time())
        try:
            conv = convert_list(_fetch(item["url"], timeout), zone)
            if conv["rules"] == 0:
                raise ValueError("nothing in it could be converted")
            if conv["records"] > MAX_RECORDS:
                raise ValueError(f"{conv['records']} records: more than {MAX_RECORDS}")
            bad = _check_zone(zone, conv["zone_text"])
            if bad:
                raise ValueError(f"the converted zone does not load: {bad}")
            changed = write_file_if_changed(path, conv["zone_text"], 0o640, 0, gid)
            st.update({"last_success": st["last_fetch"], "rules": conv["rules"], "records": conv["records"],
                       "skipped": conv["skipped"], "skipped_by_reason": conv["skipped_by_reason"],
                       "memory_mb": round(conv["records"] * KB_PER_RECORD / 1024, 1), "error": None})
            if changed:
                result["changed"].append(zone)
                if reload:
                    r = resolver_rndc(["reload", zone], timeout=120)
                    st["reloaded"] = bool(r and r.returncode == 0)
        except Exception as e:                  # noqa: BLE001 — a list's failure is its state, never the job's
            st["error"] = f"{type(e).__name__}: {e}"
            result["failed"].append(st["name"])
        result["lists"][zone] = st
    # lists no longer in the settings: their state goes; their zone files go at the next apply (deploy_resolver)
    write_file_if_changed(paths["state"], json.dumps(result["lists"], indent=1, sort_keys=True) + "\n", 0o640, 0, gid)
    return result
