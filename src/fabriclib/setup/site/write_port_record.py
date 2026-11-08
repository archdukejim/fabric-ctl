import json
import os


def write_port_record(path, port, cidr):
    """Purpose: say which port the site holds while it runs, so setup's firewall step keeps it open and the plan says so
             (manual 1.3.6.7): a root-only file in tmpfs, beside the hand-off's.
    Inputs:  path — the record (constants.PORT_RECORD); port — int; cidr — str or None.
    Returns: None; the file holds {"port", "cidr", "pid"}, this process being the one holding the site.
    Fails:   OSError.
    Feeds:   setup/site/guided_site."""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"port": port, "cidr": cidr, "pid": os.getpid()}, f)
