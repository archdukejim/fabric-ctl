import os

from fabriclib.backup.sections import ORDER, SECTIONS


def _claims(base, vars_):
    """Purpose: every folder each section names, as absolute paths.
    Inputs:  base — install root; vars_ — dict of vars.yaml.
    Returns: {section: [abs path]}; an outside folder only when set and not under base.
    Fails:   never.
    Feeds:   section_paths."""
    root = os.path.normpath(base)
    out = {}
    for name in ORDER:
        paths = [os.path.join(root, *rel.split("/")) for rel in SECTIONS[name]["dirs"]]
        for key in SECTIONS[name]["outside"]:
            path = vars_.get(key)
            if path and not os.path.normpath(path).startswith(root + os.sep):
                paths.append(os.path.normpath(path))
        out[name] = paths
    return out


def section_paths(section, base, vars_):
    """Purpose: what one section packs (manual 1.3.7.3): its folders that exist, each with the deeper folders another
             section claims left out (bind9/ssl is pki's, inside dns's bind9).
    Inputs:  section — a name from sections.ORDER; base — install root (/opt/fabric); vars_ — dict of vars.yaml.
    Returns: [(abs path, [abs paths inside it to leave out])], in the registry's order. The archive names each by its
             absolute path without the leading slash (tar -C /), so it goes back where it was.
    Fails:   KeyError for an unknown section.
    Feeds:   pack_section, tests/backup/section_paths_test.py."""
    claims = _claims(base, vars_)
    others = [p for name, paths in claims.items() if name != section for p in paths]
    return [(path, sorted(p for p in others if p.startswith(path + os.sep)))
            for path in claims[section] if os.path.isdir(path)]
