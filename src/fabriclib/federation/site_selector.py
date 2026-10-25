import concurrent.futures
import os
import threading
import time

from fabriclib.common.errors import ValidationError
from fabriclib.federation.common.console_url import console_url
from fabriclib.federation.common.is_root_site import is_root_site
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.federation.console_reachable import console_reachable
from fabriclib.pki.common.ca_files import ca_files
from fabriclib.samba.replication_status import replication_status
from fabriclib.samba.site_tree_records import site_tree_records

CACHE_SECONDS = 60       # the tree with its health, kept a minute (2.1.8.30): a page load never waits on every site
_cache = {"at": 0.0, "key": None, "value": None}
_lock = threading.Lock()


def site_selector(v, federation_file, now=None):
    """Purpose: the console's site selector (decision 2.1.8.30, manual 1.8.6.12): every fabric site of the domain,
             nested under its parent, each with its console's address and its health — the domain's replication
             view (this DC's inbound neighbours from that site's DCs) and a verified-HTTPS check of its console
             (console_reachable, short timeout, in parallel). The answer is cached a minute.
    Inputs:  v — rendered vars (site_name, deploy_base_dir, what console_url reads); federation_file — the
             federation registry (this site's parent when the domain holds no record of it yet); now — epoch
             seconds, default time.time() (tests).
    Returns: {"site": this site, "tree": [node], "error": "" or why the domain's records could not be read (then
             this site alone, with its parent)}; a node is {"site", "parent", "console", "here" (this site),
             "state": "up" | "degraded" (its console answers, its replication to here fails) | "down" (no answer,
             or no console recorded), "why", "replication": "ok" | "failing" | "" (no direct neighbour), "children":
             [node]}. Roots first, then by name; a site whose parent is not in the domain is shown as a root.
    Fails:   never (each part's failure is shown in "why" or "error").
    Feeds:   agent route GET /v1/sites/tree (session)."""
    now = time.time() if now is None else now
    key = (v.get("site_name"), console_url(v))
    with _lock:
        if _cache["key"] == key and 0 <= now - _cache["at"] < CACHE_SECONDS:
            return _cache["value"]
    value = _build(v, federation_file)
    with _lock:
        _cache.update(at=now, key=key, value=value)
    return value


def _build(v, federation_file):
    """Purpose: the selector's answer, uncached.
    Inputs:  as site_selector.
    Returns: site_selector's dict.
    Fails:   never.
    Feeds:   site_selector."""
    here = str(v.get("site_name") or "")
    error = ""
    try:
        records = {r["site"]: r for r in site_tree_records()}
    except ValidationError as e:
        records, error = {}, str(e)
    parent = "" if is_root_site(federation_file) else \
        str((load_registry(federation_file).get("upstream") or {}).get("site_name") or "")
    if here:                                    # this site's own entry: as it is now (no site name: none)
        mine = records.setdefault(here, {"site": here, "parent": parent, "console": ""})
        mine["console"] = console_url(v) or mine.get("console", "")
    replication = _replication_by_site()
    root_ca = ca_files(v)[0]
    others = [r for r in records.values() if r["site"] != here]
    if os.path.exists(root_ca):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            checks = dict(zip([r["site"] for r in others],
                              pool.map(lambda r: console_reachable(r["console"], root_ca), others)))
    else:
        checks = {r["site"]: (False, "fabric's root CA is not on this host") for r in others}
    nodes = {}
    for name, r in records.items():
        up, why = (True, "") if name == here else checks[name]
        rep = replication.get(name, "")
        state = "down" if not up else ("degraded" if rep == "failing" else "up")
        if state == "degraded":
            why = "its domain controllers' replication to this site is failing"
        nodes[name] = {"site": name, "parent": r.get("parent") or "", "console": r.get("console") or "",
                       "here": name == here, "state": state, "why": why, "replication": rep, "children": []}
    roots = []
    for name in sorted(nodes):
        node = nodes[name]
        up = nodes.get(node["parent"])
        if up and not _loops(nodes, name):
            up["children"].append(node)
        else:
            roots.append(node)
    return {"site": here, "tree": roots, "error": error}


def _loops(nodes, name):
    """Purpose: whether following a site's parents comes back to it (records written by hand could): such a site is
             shown as a root, never lost.
    Inputs:  nodes — {name: node}; name — the site.
    Returns: bool.
    Fails:   never.
    Feeds:   _build."""
    seen, at = {name}, nodes[name]["parent"]
    while at in nodes:
        if at in seen:
            return True
        seen.add(at)
        at = nodes[at]["parent"]
    return False


def _replication_by_site():
    """Purpose: the domain's replication view per site: this DC's inbound neighbours grouped by the site their DC is
             in (the NTDS Settings DN names it: CN=NTDS Settings,CN=<dc>,CN=Servers,CN=<site>,CN=Sites,...).
    Inputs:  none (this site's DC).
    Returns: {site: "ok" | "failing"}; a site with no direct neighbour here is absent.
    Fails:   never (a DC that does not answer gives {}).
    Feeds:   _build."""
    out = {}
    for n in replication_status().get("neighbours") or []:
        parts = [p.split("=", 1) for p in str(n.get("from") or "").split(",")]
        if len(parts) > 4 and parts[2][0].upper() == "CN" and parts[2][1].lower() == "servers":
            site = parts[3][1].lower()
            failing = int(n.get("failures") or 0) > 0
            out[site] = "failing" if failing or out.get(site) == "failing" else "ok"
    return out
