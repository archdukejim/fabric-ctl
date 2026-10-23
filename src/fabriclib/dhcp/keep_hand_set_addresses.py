import datetime
import json
import os

from fabriclib.dhcp.common.hand_set_path import hand_set_path
from fabriclib.dhcp.hand_set_addresses import hand_set_addresses


def keep_hand_set_addresses(v):
    """Purpose: keep the apply's addresses set by hand for the hourly cleanup of DHCP names left behind
             (fabric-dhcp-names.timer, 2.1.10.22): the plan's published names are read from the DC at the apply only.
    Inputs:  v — the apply's checked settings (install_kea, dhcp.ddns, dns, deploy_base_dir).
    Returns: the file's path; None when Kea or its DNS registration is off (a file left by an earlier apply is
             removed then).
    Fails:   OSError writing the file.
    Feeds:   deploy/apply_deployment."""
    path = hand_set_path(v)
    if not v.get("install_kea") or not (v.get("dhcp") or {}).get("ddns", True):
        if os.path.exists(path):
            os.remove(path)
        return None
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"written": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                   "addresses": hand_set_addresses(v)}, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path
