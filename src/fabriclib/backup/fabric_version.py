def fabric_version(text):
    """Purpose: a fabric version as a comparable tuple.
    Inputs:  text — "0.10.1", "0.10.1~git…", or "?".
    Returns: (major, minor, patch), or None when it is not a version.
    Fails:   never.
    Feeds:   restore_bundle, check_whole_restore."""
    parts = (text or "").split("~")[0].split(".")
    try:
        return tuple(int(p) for p in parts[:3]) if len(parts) >= 3 else None
    except ValueError:
        return None
