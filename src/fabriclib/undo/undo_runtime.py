import json
import os
import subprocess
import time

from fabriclib.common.systemctl_up import systemctl_up
from fabriclib.common.restore_original import restore_original
from fabriclib.security.hardened_daemon_settings import DAEMON_JSON, HARDENED


def _strip_hardening(path):
    """Purpose: take fabric's hardening out of daemon.json when no copy of the earlier file was kept (an install
             set up before copies were kept): every key still holding fabric's value goes; other keys stay.
    Inputs:  path — daemon.json.
    Returns: True if the file changed.
    Fails:   json.JSONDecodeError / OSError.
    Feeds:   undo_runtime."""
    if not os.path.exists(path):
        return False
    with open(path) as f:
        text = f.read().strip()
    current = json.loads(text) if text else {}
    out = {k: val for k, val in current.items() if k == "log-opts" or HARDENED.get(k) != val}
    opts = {k: val for k, val in (out.get("log-opts") or {}).items() if HARDENED["log-opts"].get(k) != val}
    out.pop("log-opts", None)
    if opts:
        out["log-opts"] = opts
    if out == current:
        return False
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    return True


def undo_runtime(config_dir, restart=True):
    """Purpose: undo the `runtime` host change (manual 1.2.9.5): Docker's daemon.json as it was before
             fabric hardened it, and Docker restarted to apply it.
    Inputs:  config_dir — the install's config folder (the kept copy: common/keep_original); restart — restart Docker
             when the file changed (False in tests).
    Returns: list of str, what was done (empty when there was nothing to undo).
    Fails:   OSError / json.JSONDecodeError on daemon.json; CalledProcessError from `systemctl restart docker`;
             RuntimeError when Docker does not answer within about 60 s afterwards.
    Feeds:   undo/undo_group (`fabricctl setup --undo runtime`).
    Notes:   the running daemon has live-restore on (fabric's hardening), so containers keep running through this
             restart; without a kept copy only the keys still holding fabric's values are removed."""
    how = restore_original(DAEMON_JSON, config_dir)
    if how is None:
        done = [f"{DAEMON_JSON}: fabric's hardening removed (no copy of the earlier file was kept)"] \
            if _strip_hardening(DAEMON_JSON) else []
    else:
        done = [f"{DAEMON_JSON}: {'put back as it was' if how == 'restored' else 'removed (it did not exist before)'}"]
    if done and restart:
        systemctl_up(["docker"], restart=True)
        for _ in range(12):
            if subprocess.run(["docker", "info"], capture_output=True).returncode == 0:
                break
            time.sleep(5)
        else:
            raise RuntimeError("Docker did not come back after restoring its daemon settings; "
                               "check `journalctl -u docker`")
        done.append("Docker restarted")
    return done
