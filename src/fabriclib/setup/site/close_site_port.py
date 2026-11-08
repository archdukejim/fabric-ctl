import os
import shlex
import subprocess

from fabriclib.setup.site.constants import PORT_RECORD, RULE_COMMENT


def close_site_port(record=PORT_RECORD, run=subprocess.run):
    """Purpose: take away what the site opened (manual 1.3.6.7, global Rule 12): every ufw rule carrying the site's
             comment, and the record. Acts on positive evidence, the comment, never on a rule merely looking alike;
             so it also clears what a killed run left behind.
    Inputs:  record — the site's record; run — subprocess.run.
    Returns: the rules removed (list of str, as ufw shows them).
    Fails:   never for ufw missing; a rule ufw will not delete is left and returned out of the list (the caller's
             check of what remains is `ufw show added`).
    Feeds:   setup/site/guided_site."""
    try:
        os.remove(record)
    except OSError:
        pass
    try:
        out = run(["ufw", "show", "added"], capture_output=True, text=True).stdout
    except OSError:
        return []
    removed = []
    for line in out.splitlines():
        if RULE_COMMENT not in line or not line.strip().startswith("ufw "):
            continue
        if run(["ufw", "delete", *shlex.split(line)[1:]], capture_output=True, text=True).returncode == 0:
            removed.append(line.strip())
    return removed
