from fabriclib.backup.sections import ORDER, SECTIONS, SETTINGS_KEYS


def _owns(pattern, key):
    """Purpose: whether one section pattern names a key: a pattern ending in "_" is a prefix, any other the key
             itself or its prefix followed by "_" ("dns_filter" names dns_filter and dns_filter_groups).
    Inputs:  pattern — str from SECTIONS[..]["keys"]; key — a vars.yaml key.
    Returns: bool.
    Fails:   never.
    Feeds:   section_of_key."""
    if pattern.endswith("_"):
        return key.startswith(pattern)
    return key == pattern or key.startswith(pattern + "_")


def section_of_key(key):
    """Purpose: the one section that owns a vars.yaml key (manual 1.3.7.3): the section a section restore replaces
             it with; a key no section names belongs to settings.
    Inputs:  key — a top-level vars.yaml key.
    Returns: a section name from sections.ORDER.
    Fails:   ValueError when two sections name the key (a registry error, caught by its test).
    Feeds:   restore_section (the keys it replaces), tests/backup/section_of_key_test.py."""
    if key in SETTINGS_KEYS:
        return "settings"
    owners = [name for name in ORDER if any(_owns(p, key) for p in SECTIONS[name]["keys"])]
    if len(owners) > 1:
        raise ValueError(f"vars.yaml key {key} is named by {', '.join(owners)}: a key belongs to one section")
    return owners[0] if owners else "settings"
