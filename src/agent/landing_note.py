def landing_note(stale):
    """Purpose: what DNS' Review says when the landing page's certificate no longer holds the page's names (decision
             2.1.8.29): DNS' Apply reloads only BIND, so a full apply on the host issues it again.
    Inputs:  stale — dns/landing_cert_stale's answer.
    Returns: str, "" when nothing waits.
    Fails:   never.
    Feeds:   agent/post_pending (_finish_dns: the publish step's note); the dev preview's fake finish."""
    if not stale:
        return ""
    said = [f"lacks {', '.join(stale['missing'])}" if stale["missing"] else "",
            f"still names {', '.join(stale['extra'])}" if stale["extra"] else ""]
    return ("the landing page's certificate " + " and ".join(s for s in said if s) + ": a full apply on the host "
            "(sudo fabricctl --apply) issues it again")
