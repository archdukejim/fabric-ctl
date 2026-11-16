import shlex


def ufw_own_rule_args(rule):
    """Purpose: the arguments after `ufw` of one of the host's own rules as `ufw show added` prints it, split as a
             shell does (manual 1.2.8, 2.1.2.13): its comment keeps its words and loses its quotes. Split on spaces,
             `comment 'own-app'` reached ufw with the quotes and ufw refused it (`Invalid syntax`), so the rule was
             neither removed nor put back (the 0.10.0 rc's rehearsal, 2.3.1.57).
    Inputs:  rule — str, e.g. "ufw allow 8443/tcp comment 'own-app'".
    Returns: list of str without the leading `ufw` (["allow", "8443/tcp", "comment", "own-app"]); [] for a line that is
             not a ufw command or does not split (an unclosed quote).
    Fails:   never.
    Feeds:   setup/configure_firewall (removing them), undo/undo_firewall (putting them back)."""
    try:
        words = shlex.split(rule)
    except ValueError:
        return []
    return words[1:] if len(words) > 1 and words[0] == "ufw" else []
