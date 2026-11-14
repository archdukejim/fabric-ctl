from fabriclib.common.errors import ValidationError


def rule_number(text, rules):
    """Purpose: a rule's number as typed, checked against the list (manual 1.10.4.48.5).
    Inputs:  text — str or int; rules — the site's list.
    Returns: int, 1 to len(rules).
    Fails:   ValidationError for anything else, saying the range.
    Feeds:   remove_rule, move_rule."""
    try:
        n = int(str(text).strip())
    except ValueError:
        n = 0
    if not 1 <= n <= len(rules):
        raise ValidationError(f"rule {text}: the site's rules are numbered 1 to {len(rules)} (ipam rule lists them)")
    return n
