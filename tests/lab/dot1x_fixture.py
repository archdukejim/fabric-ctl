#!/usr/bin/env python3
"""The 802.1X lab suite's fixture on the fabric host (manual 1.11.1.5): device roles, devices and a device certificate
made with fabric's own functions, as the console makes them. Run by tests/lab/dot1x.sh over SSH, as root, with
fabric's installed library on the path:

    sudo PYTHONPATH=/usr/lib/fabricctl/fabric/lib python3 - setup <supplicant-mac> <printer-mac>  < dot1x_fixture.py
    ... - disable|enable <device> <its mac>
    ... - cleanup

setup prints one JSON object: {"cert", "key", "chain"} for the supplicant's device certificate (lab-ubuntu); the key
leaves this host only on that stdout, to the test's own SSH channel.
"""
import json
import sys

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.directory.add_device import add_device
from fabriclib.directory.add_role import add_role
from fabriclib.directory.remove_device import remove_device
from fabriclib.directory.remove_role import remove_role
from fabriclib.directory.update_device import update_device
from fabriclib.pki.issue_key_pair import issue_key_pair

ACTOR = "lab-dot1x"
KINDS = {"lab-ubuntu": ("laptop", "lab-staff"), "lab-printer": ("printer", "lab-iot")}
ROLES = {"lab-staff": {"permissions": ["network:eap-tls"], "vlan": "20", "priority": 50},
         "lab-iot": {"permissions": ["network:mab"], "vlan": "30", "priority": 50}}


def _quiet(fn, *args):
    try:
        fn(*args)
    except ValidationError:
        pass                       # already there, or already gone: the fixture is idempotent


def main(argv):
    v = load_vars()
    if argv[:1] == ["setup"] and len(argv) == 3:
        for name, fields in ROLES.items():
            _quiet(add_role, v, ACTOR, name, fields, "cli")
        for (device, (kind, role)), mac in zip(KINDS.items(), argv[1:]):
            _quiet(add_device, v, ACTOR, device, {"type": kind, "roles": [role], "macs": [mac]}, "cli")
        issued = issue_key_pair(v, ACTOR, "lab-ubuntu", days=2, device="lab-ubuntu", source="cli")
        print(json.dumps({"cert": issued["cert"], "key": issued["key"], "chain": issued["chain"]}))
        return 0
    if argv[:1] in (["disable"], ["enable"]) and len(argv) == 3 and argv[1] in KINDS:
        kind, role = KINDS[argv[1]]                 # update_device replaces every field: give them all
        update_device(v, ACTOR, argv[1], {"type": kind, "roles": [role], "macs": [argv[2]],
                                          "enabled": argv[0] == "enable"}, "cli")
        return 0
    if argv == ["cleanup"]:
        for device in KINDS:
            _quiet(remove_device, v, ACTOR, device, "cli")
        for role in ROLES:
            _quiet(remove_role, v, ACTOR, role, "cli")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
