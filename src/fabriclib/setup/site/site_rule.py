from fabriclib.setup.site.constants import RULE_COMMENT


def site_rule(port, cidr):
    """Purpose: the ufw rule that lets browsers reach the site, as the words after `ufw allow` (manual 1.3.6.7); the
             comment is how fabric later knows the rule is its own.
    Inputs:  port — int; cidr — the LAN (str), or None when it could not be detected: from anywhere.
    Returns: list of str.
    Fails:   never.
    Feeds:   setup/site/open_site_port, setup/site/keep_site_port."""
    return ["from", cidr or "any", "to", "any", "port", str(port), "proto", "tcp", "comment", RULE_COMMENT]
