#!/usr/bin/env python3
"""The last step of replacing Kea's DNS key (decision 2.1.10.42, manual 1.10.4.43): BIND's keys and grants rendered
again from fabric's templates without the old key, written, `rndc reconfig`; only then the old key removed from the
secrets and audited. BIND refusing: nothing removed, said. rndc and the secrets' store stood in for (the real BIND
and Kea: tests/kea/reload.py).

    python3 tests/dhcp/kea_key/drop_old_key_test.py
"""
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.dhcp.kea_key.drop_old_key import drop_old_key  # noqa: E402

FAILED = 0
OLD = {"name": "kea-ddns", "secret": "b2xkLXNlY3JldA==", "made": "2025-11-28"}


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def run(tmp, refuse=False):
    os.makedirs(os.path.join(tmp, "bind9", "config"), exist_ok=True)
    asked, saved, audited = [], [], []
    uid, gid = os.getuid(), os.getgid()
    final = {"deploy_base_dir": tmp, "install_kea": True, "domain": "lan.test", "dhcp": {"ddns": True},
             "service_users": {"bind": {"uid": uid, "gid": gid}}}
    context = {"kea_ddns_key": "kea-ddns-20261024", "kea_ddns_secret": "bmV3LXNlY3JldA==", "kea_ddns_old": OLD,
               "tsig_keys": [], "tsig_secrets": {}, "bind_acls": {"lan": ["any"]}, "dns": {}, "peers": [],
               "local_zones": [], "reverse_zone_names": [], "dhcp_reverse_zones": []}

    def rndc(args, timeout=15):
        asked.append(args)
        return subprocess.CompletedProcess(args, 1 if refuse else 0, "", "rndc: 'reconfig' failed: bad key"
                                           if refuse else "")
    try:
        name = drop_old_key(final, context, jinja_env(os.path.join(REPO, "templates")), OLD, rndc_call=rndc,
                            save=lambda update, path: saved.append(update),
                            audit=lambda *a: audited.append(a), secrets_path="/nowhere")
        error = None
    except ValidationError as e:
        name, error = None, str(e)
    keys = open(os.path.join(tmp, "bind9", "config", "named.conf.keys")).read()
    zones = open(os.path.join(tmp, "bind9", "config", "named.conf.zones")).read()
    return name, error, asked, saved, audited, keys, zones, os.stat(os.path.join(tmp, "bind9", "config",
                                                                                 "named.conf.keys")).st_mode


with tempfile.TemporaryDirectory() as tmp:
    name, error, asked, saved, audited, keys, zones, mode = run(tmp)
    check("BIND's keys and grants written without the old key, the new one kept; rndc reconfig; the keys file "
          "0600", name == "kea-ddns" and error is None and 'key "kea-ddns-20261024"' in keys
          and 'key "kea-ddns"' not in keys and OLD["secret"] not in keys
          and 'grant "kea-ddns-20261024" zonesub A AAAA DHCID;' in zones and 'grant "kea-ddns" ' not in zones
          and asked == [["reconfig"]] and oct(mode & 0o777) == "0o600", (error, keys, zones, asked))
    check("then the old key removed from fabric's secrets and the replacement audited",
          saved == [{"kea_ddns_old": None}] and audited and audited[0][1] == "KEA_KEY_ROTATE"
          and "kea-ddns dropped, kea-ddns-20261024 in force" in audited[0][2], (saved, audited))
with tempfile.TemporaryDirectory() as tmp:
    name, error, asked, saved, audited, keys, zones, mode = run(tmp, refuse=True)
    check("BIND refusing the reconfig: refused loudly, the old key kept in the secrets (the next apply drops it), "
          "nothing audited", error and "did not drop Kea's old key kea-ddns" in error and "bad key" in error
          and saved == [] and audited == [], (error, saved))

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
