"""Seed and snapshot what an upgrade must keep (manual 2.1.1.36), on a real install, as root on the fabric host.

    python3 upgrade_state.py seed       add state an operator would have: a person, a DNS record shown on the
                                        landing page, a device certificate, a name the DNS filter blocks (the
                                        resolver's dns_filter_block)
    python3 upgrade_state.py snapshot   print it as JSON (no secret values: hashes only), to compare before and after

Uses only what both the previous release and the candidate have (fabriclib's functions, samba-tool, the files).
"""
import hashlib
import json
import os
import re
import subprocess
import sys

import yaml

sys.path.insert(0, "/opt/fabric/lib")
VARS = "/opt/fabric/config/vars.yaml"
RULE = "upgrade-test.invalid"
PERSON = "carol"

# secrets a release changes by design: compared by presence only
ROTATED = {"keycloak_db_password"}


def _sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def _sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def seed():
    from fabriclib.common.errors import ValidationError
    from fabriclib.directory.create_person import create_person
    from fabriclib.dns.add_record import add_record
    v = yaml.safe_load(open(VARS))
    try:
        create_person(v, "test", PERSON, "Carol", "Upgrade", "carol@example.invalid", source="test")
        print(f"{PERSON} created")
    except ValidationError as e:
        print(f"{PERSON}: {e}")
    zone = next(iter((yaml.safe_load(open(VARS)).get("dns") or {}) or {v["domain"]: None}))
    try:
        add_record("test", zone, "A", {"name": "upgrade-test", "ip": "192.0.2.55", "link": "on",
                                       "link_label": "Upgrade test"}, source="cli")
        print(f"record upgrade-test in {zone}")
    except ValidationError as e:
        print(f"record: {e}")
    from fabriclib.common.save_vars import save_vars
    from fabriclib.common.vars_lock import vars_lock
    with vars_lock():                        # a name the DNS filter blocks (applied by the --apply after the seed)
        data = yaml.safe_load(open(VARS))
        if RULE not in (data.get("dns_filter_block") or []):
            data["dns_filter_block"] = (data.get("dns_filter_block") or []) + [RULE]
            save_vars(data, VARS)
    print(f"blocked {RULE}")


def snapshot():
    from fabriclib.secrets.load_secrets import load_secrets
    v = yaml.safe_load(open(VARS))
    out = {}
    root = _sh(f"curl -s --max-time 10 http://{v['host_ip']}/certs/root-ca.pem")
    open("/tmp/upgrade-root.pem", "w").write(root)
    out["root_ca"] = _sha(root) if "BEGIN CERTIFICATE" in root else "missing"
    for user in (PERSON, v.get("webui_admin_user", "")):
        shown = _sh(f"docker exec samba samba-tool user show {user} "
                    "--attributes=objectGUID,pwdLastSet,msDS-KeyVersionNumber,uidNumber -s /data/etc/smb.conf 2>/dev/null")
        out[f"person {user}"] = sorted(ln for ln in shown.splitlines() if ln and not ln.startswith("dn:"))
    cert = "/root/upgrade-test-carol.pem"          # the device certificate, taken out of its .p12 at seeding
    out["issued"] = (_sh(f"openssl x509 -in {cert} -noout -serial -fingerprint -sha256").strip()
                     + " | " + _sh(f"openssl verify -CAfile /tmp/upgrade-root.pem {cert} 2>&1").strip()
                     if os.path.exists(cert) else "missing")
    secrets = load_secrets(v=v)
    # one hash per secret: a release may add secrets; Keycloak's database password rotates by design (2.1.7.4)
    out["secrets"] = {k: _sha(json.dumps(secrets[k], sort_keys=True, default=str)) for k in sorted(secrets)
                      if k not in ROTATED}
    out["dns record"] = _sh(f"dig +short -p {v.get('bind_dns_port', 53)} @{v['host_ip']} upgrade-test.{v['domain']}").strip()
    out["dns filter rule"] = RULE in (v.get("dns_filter_block") or [])
    out["security"] = sorted(ln.split()[0] + " " + ln.split()[1] for ln in _sh("fabricctl security").splitlines()
                             if re.match(r"[a-z0-9-]+ +[a-z]+( |$)", ln))
    print(json.dumps(out, indent=1, sort_keys=True))


if __name__ == "__main__":
    {"seed": seed, "snapshot": snapshot}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
