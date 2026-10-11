import json
import time
import urllib.request

from fabriclib.common.service_user import service_user
from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.dns_filter.common.adguard_paths import adguard_paths

URL = "https://adguardteam.github.io/HostlistsRegistry/assets/filters.json"
GROUPS = {1: "General", 2: "Other", 3: "Regional", 4: "Security"}


def fetch_catalogue(v, timeout=60):
    """Purpose: AdGuard's list catalogue (its HostlistsRegistry, manual 1.12.3.5) for the web console's checkboxes,
             read from the registry and kept in <base>/dnsfilter/catalogue.json: never shipped with a release
             (2.3.12.1.11 Q13). Run by the lists job (it has the internet; fabric-agent has not), which then keeps a
             copy of every list in it.
    Inputs:  v — rendered vars (deploy_base_dir, service_users.adguard); timeout — seconds.
    Returns: {"fetched": time (epoch), "lists": [{name, url, description, homepage, group}]}, the registry's lists
             that are not deprecated, by group then name.
    Fails:   urllib.error.URLError, OSError, ValueError (not the registry's JSON): the caller keeps the last copy.
    Feeds:   dns_filter/refresh_lists."""
    with urllib.request.urlopen(urllib.request.Request(URL, headers={"User-Agent": "fabric-dns-filter"}),
                                timeout=timeout) as r:                     # noqa: S310 (a fixed https URL)
        data = json.loads(r.read(8 * 1024 * 1024))
    lists = [{"name": f.get("name") or "", "url": f.get("downloadUrl") or "", "description": f.get("description") or "",
              "homepage": f.get("homepage") or "", "group": GROUPS.get(f.get("groupId"), "Other")}
             for f in data.get("filters") or [] if f.get("downloadUrl") and not f.get("deprecated")]
    if not lists:
        raise ValueError("the registry listed no lists")
    lists.sort(key=lambda f: (list(GROUPS.values()).index(f["group"]), f["name"].lower()))
    out = {"fetched": int(time.time()), "lists": lists}
    _, gid = service_user(v, "adguard")
    write_file_if_changed(adguard_paths(v)["catalogue"], json.dumps(out) + "\n", 0o640, 0, gid)
    return out
