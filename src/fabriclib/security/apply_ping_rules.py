import os
import re
import shutil

from fabriclib.common.keep_original import ORIGINALS
from fabriclib.ipam.rules.access_sources import access_sources

BEFORE = "/etc/ufw/before.rules"
BEFORE6 = "/etc/ufw/before6.rules"
BEGIN = "# fabric: ping, from the site's access rules (manual 1.10.4.48.3): begin"
END = "# fabric: ping: end"
# ufw's stock lines that answer every echo request (IPv4, IPv6)
STOCK = "-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT"
STOCK6 = "-A ufw6-before-input -p icmpv6 --icmpv6-type echo-request -j ACCEPT"
BLOCK = re.compile(re.escape(BEGIN) + r"\n.*?" + re.escape(END) + r"\n", re.S)


def _rewrite(path, stock, lines, keep_as):
    """Purpose: one of ufw's before-rules files with its echo-request answer replaced by fabric's block.
    Inputs:  path — the file; stock — ufw's own line to replace; lines — the block's rule lines; keep_as — the copy's
             path for uninstall (written once, the first time).
    Returns: bool: the file changed.
    Fails:   OSError reading or writing.
    Feeds:   apply_ping_rules."""
    text = open(path).read()
    block = "\n".join([BEGIN, *lines, END]) + "\n"
    if BLOCK.search(text):
        new = BLOCK.sub(lambda _m: block, text, count=1)
    elif stock + "\n" in text:
        if not os.path.exists(keep_as):
            os.makedirs(os.path.dirname(keep_as), mode=0o700, exist_ok=True)
            shutil.copy2(path, keep_as)
        new = text.replace(stock + "\n", block, 1)
    else:
        return False                    # changed by hand: left as it is, and said by the caller
    if new == text:
        return False
    with open(path, "w") as f:
        f.write(new)
    return True


def apply_ping_rules(v, config_dir, before=BEFORE, before6=BEFORE6):
    """Purpose: ping answered only from the networks the site's access rules allow `ping` (manual 1.10.4.48.3,
             decision 2.1.10.56): ufw's line that answers every IPv4 echo request becomes one line per allowed
             network, and IPv6's is left out (fabric serves no IPv6: 2.1.10.54). The files as they were are kept once
             in <config>/host-originals/ for uninstall to put back (undo_firewall). ICMP errors and anything of a
             connection already allowed still pass (ufw's other lines).
    Inputs:  v — fabric vars (access_sources, or host_ip, lan_cidr and the plan last read); config_dir — the
             install's config folder; before, before6 — the files (tests give their own).
    Returns: {"changed": bool (ufw must reload), "from": [CIDR, ...], "skipped": [str, ...] (a file missing, or
             without ufw's own line: changed by hand, left)}.
    Fails:   OSError reading or writing the files.
    Feeds:   setup/configure_firewall."""
    nets = [c for c in access_sources(v)["ping"] if ":" not in c]
    out = {"changed": False, "from": nets, "skipped": []}
    lines = [f"-A ufw-before-input -p icmp --icmp-type echo-request -s {c} -j ACCEPT" for c in nets]
    for path, stock, rules, name in ((before, STOCK, lines, "ufw.before.rules"),
                                     (before6, STOCK6, [], "ufw.before6.rules")):
        if not os.path.exists(path):
            out["skipped"].append(f"{path}: not there")
            continue
        if _rewrite(path, stock, rules, os.path.join(config_dir, ORIGINALS, name)):
            out["changed"] = True
        elif BEGIN not in open(path).read():
            out["skipped"].append(f"{path}: ufw's own echo-request line is not there (changed by hand): left")
    return out
