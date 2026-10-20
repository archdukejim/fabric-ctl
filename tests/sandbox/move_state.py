"""What the move to 0.8.0 keeps and makes new (decision 2.1.1.60, manual 3.3.5.3), read on a running install, as root
inside the move test's sandbox (tests/sandbox/move.sh), with what both 0.7.1 and 0.8.0 have (the rendered vars.yaml,
the secrets' loader, dig).

    python3 move_state.py   print JSON: kept (the zones, the admin's records as BIND serves them, the TSIG keys'
                            names and rights, the parts and their settings) and new (hashes only: the root CA, the
                            TSIG secrets)
"""
import hashlib
import json
import subprocess
import sys

import yaml

sys.path.insert(0, "/opt/fabric/lib")
VARS = "/opt/fabric/config/vars.yaml"
# the records the move test's vars file adds: (name, type), each asked of BIND
RECORDS = [("nas.move.test", "A"), ("files.move.test", "CNAME"), ("printer.extra.test", "A")]
PARTS = ("install_keycloak", "install_webui", "install_fluentbit", "install_kea", "install_freeradius", "dns_filter",
         "dns_filter_upstreams", "log_forwarding", "host_ram_capacity", "ad_password_policy", "signin_kerberos",
         "ntp_set_clock", "friendly_name", "domain", "ad_domain")


def _sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def main():
    from fabriclib.secrets.load_secrets import load_secrets
    v = yaml.safe_load(open(VARS))
    port, ip = v.get("bind_dns_port", 53), v["host_ip"]
    kept = {
        "zones": sorted(z if z != "dynamic_zone_var" else v["domain"] for z in (v.get("dns") or {})),
        "records": {f"{n} {t}": _sh(f"dig +short -p {port} @{ip} {t} {n}").strip() for n, t in RECORDS},
        "tsig keys": sorted(({k: val for k, val in key.items() if k != "secret"} for key in v.get("tsig_keys") or []),
                            key=lambda key: key["name"]),
        "parts": {k: v.get(k) for k in PARTS},
    }
    secrets = load_secrets(v=v)
    root = _sh(f"curl -s --max-time 10 http://{ip}/certs/root-ca.pem")
    new = {"root ca": _sha(root) if "BEGIN CERTIFICATE" in root else "missing",
           "tsig secrets": {k: _sha(str(s)) for k, s in sorted((secrets.get("tsig_secrets") or {}).items())}}
    print(json.dumps({"kept": kept, "new": new}, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
