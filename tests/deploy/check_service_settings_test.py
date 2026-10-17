"""The settings every service's container starts with, checked before an apply renders anything (the owner's answer of
2026-10-12 for the gaps of 2.3.1.20.2): images, fabric's container addresses, the uid/gid block. Pure logic.
    python3 tests/deploy/check_service_settings_test.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.deploy.check_service_settings import check_service_settings  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


DIGEST = "@sha256:" + "a" * 64
GOOD = {"fabric_subnet": "10.255.0.0/24", "ip_adguard": "10.255.0.34", "ip_bind9": "10.255.0.30",
        "ip_fabric_gateway": "10.255.0.1", "image_adguard": "adguard/adguardhome:v0.107.79" + DIGEST,
        "image_fabric_bind9": "ghcr.io/archdukejim/open-fabric/bind9:0.7.0-rc.126" + DIGEST,
        "image_kea": "fabric/kea:local", "image_fabric_webui": "", "image_registry_port": "registry.lan:5000/x/y:1",
        "image_pins": [], "image_prune": True, "image_rolled_back": [], "image_signature_check": True,
        "posix_id_start": 1000000, "posix_id_block": 1000000}


def refused(**change):
    try:
        check_service_settings({**GOOD, **change})
    except ValidationError as e:
        return str(e)
    return None


# covers: setting:image_adguard setting:ip_adguard setting:posix_id_start setting:posix_id_block +
# covers: setting:image_kea +
check("the defaults pass: digests, local builds, a pending image, a registry with a port, a million-wide block",
      refused() is None, refused())
check("a root block at another million passes", refused(posix_id_start=3000000) is None, refused(posix_id_start=3000000))

# covers: setting:image_adguard setting:image_kea -
for key, bad in (("image_adguard", "AdGuard/AdGuardHome:latest"), ("image_adguard", "adguard home"),
                 ("image_kea", "fabric/kea@sha256:short"), ("image_adguard", 7)):
    why = refused(**{key: bad})
    check(f"refused: {key} {bad!r} is not an image, the setting named", why and key in why and "image" in why, why)

# covers: setting:ip_adguard -
for bad, said in (("10.255.1.34", "not a host address in fabric's network"), ("10.255.0.0", "not a host address"),
                  ("10.255.0.255", "not a host address"), ("10.255.0.300", "not an IPv4 address"),
                  ("10.255.0.30", "is already ip_adguard's address")):     # the second of the two is named
    why = refused(ip_adguard=bad)
    check(f"refused: ip_adguard {bad} ({said})", why and "ip_adguard" in why and said in why, why)
why = refused(fabric_subnet="10.255.0.0/33")
check("refused: a fabric_subnet that is not a network", why and "fabric_subnet" in why, why)

# covers: setting:posix_id_start setting:posix_id_block -
for change, said in (({"posix_id_start": 999}, "posix_id_start must be a whole number, at least 1000"),
                     ({"posix_id_start": "1e6"}, "posix_id_start must be a whole number"),
                     ({"posix_id_block": 10}, "posix_id_block must be a whole number, at least 1000"),
                     ({"posix_id_start": 2147000000}, "goes past 2147483647"),
                     # an install's block from before 0.7.0 is no longer served (2.1.6.51, S11)
                     ({"posix_id_start": 5001}, "posix_id_start must be a multiple of 1000000"),
                     ({"posix_id_block": 100000}, "posix_id_block must be 1000000"),
                     ({"posix_id_start": 5001, "posix_id_block": 10000}, "posix_id_start must be a multiple")):
    why = refused(**change)
    check(f"refused: {change} ({said})", why and said in why, why)
for change in ({"posix_id_start": 5001}, {"posix_id_block": 100000}):
    why = refused(**change)
    check(f"an older block's refusal ({change}) says to install fresh, why, and where the steps are (2.1.6.54)",
          why and "before 0.7.0" in why and "install it fresh" in why and "no migration" in why and "3.3.5" in why,
          why)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
