import re

from fabriclib.federation.constants import MIN_UPSTREAM_VERSION

_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def upstream_version_problem(inv):
    """Purpose: why a site may not join with this invitation, if it may not: its upstream is older than 0.8.0, which
             does not name a joining site's domain controller (2.1.6.65, revised 2026-10-18). An invitation carries its
             upstream's version (create_invitation); one without is an older upstream's.
    Inputs:  inv — decode_invitation's dict ("version": "" when the invitation names none).
    Returns: str, the problem, saying to upgrade the upstream first; "" when the upstream is 0.8.0 or later.
    Fails:   never.
    Feeds:   setup/collect_vars (--join: before anything is asked or done), federation/join_upstream (before
             anything is made, sent or staged)."""
    version = str(inv.get("version") or "").strip()
    m = _VERSION.match(version)
    if m and tuple(int(x) for x in m.groups()) >= MIN_UPSTREAM_VERSION:
        return ""
    oldest = ".".join(str(n) for n in MIN_UPSTREAM_VERSION)
    said = f"fabric {version}" if version else "a fabric older than 0.8.0 (the invitation names no version)"
    return (f"the upstream {inv.get('upstream') or ''} runs {said}: a site joins an upstream of {oldest} or later "
            "(2.1.6.65). Upgrade the upstream first, then make a new invitation there; nothing was sent or changed")
