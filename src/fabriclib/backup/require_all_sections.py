from fabriclib.common.errors import ValidationError


def require_all_sections(manifest):
    """Purpose: a whole restore only from a bundle of the whole install (manual 1.3.7.6): a section restore's safety
             bundle holds that section alone, the others packed empty, and restored whole it would bring back an
             install without its domain (found by the sandbox, 2026-11-23).
    Inputs:  manifest — the bundle's (check_bundle's): "only", the sections it was made for, when not all.
    Returns: None.
    Fails:   ValidationError naming the sections it holds and how to restore them.
    Feeds:   restore_bundle, check_whole_restore."""
    only = manifest.get("only")
    if only:
        raise ValidationError(f"this bundle holds only {', '.join(only)} (a section restore's safety bundle): restore "
                              "it by section (fabricctl restore <bundle> --section <name>, or the console's Restore…), "
                              "not whole")
