import re

_NAME = re.compile(r"^([a-z0-9][a-z0-9+.-]*)")


def dependency_names(field):
    """Purpose: the alternatives of each dependency in a Depends-style field, as package names.
    Inputs:  field — str, e.g. "libc6 (>= 2.34), python3:any | python3-minimal", or None.
    Returns: list of lists of str (one list of alternatives per dependency); version and architecture qualifiers
             dropped.
    Fails:   never.
    Feeds:   resolve_packages, export_packages."""
    out = []
    for dep in filter(None, (d.strip() for d in (field or "").split(","))):
        alts = []
        for alt in dep.split("|"):
            m = _NAME.match(alt.strip())
            if m:
                alts.append(m.group(1))
        if alts:
            out.append(alts)
    return out
