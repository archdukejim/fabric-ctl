import os
import subprocess

from fabriclib.security.ufw_rule import RECORDS, ufw_rule
from fabriclib.setup.site.constants import RULE_COMMENT

OWN_RULES = "host-originals/ufw.own-rules"     # in the config folder: the host's rules fabric removed (2.1.2.13)


def host_own_rules(config_dir, planned=()):
    """Purpose: the ufw rules on this host that fabric did not add — the host's own (2.1.2.13): every rule ufw lists as
             added, less fabric's (its records, what this run plans to add, and web-guided setup's site's rule,
             1.3.6.7).
    Inputs:  config_dir — the install's config folder (security/ufw_rule RECORDS); planned — (kind, entry) pairs
             fabric is about to add.
    Returns: list of str, each as ufw shows it ("ufw allow …"), in ufw's order; [] without ufw.
    Fails:   OSError reading a record.
    Feeds:   consent/plan_own_rules, setup/configure_firewall."""
    try:
        out = subprocess.run(["ufw", "show", "added"], capture_output=True, text=True).stdout
    except FileNotFoundError:
        return []
    fabric = {"ufw allow " + " ".join(ufw_rule(kind, entry)) for kind, entry in planned}
    for kind, name in RECORDS.items():
        record = os.path.join(config_dir, name)
        if os.path.exists(record):
            fabric |= {"ufw allow " + " ".join(ufw_rule(kind, x if kind != "ssh" or "@" in x else f"{x}@22"))
                       for x in open(record).read().split()}
    return [line.strip() for line in out.splitlines()
            if line.strip().startswith("ufw ") and line.strip() not in fabric and RULE_COMMENT not in line]
