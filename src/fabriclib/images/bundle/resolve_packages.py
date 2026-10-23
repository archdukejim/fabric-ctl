from fabriclib.common.errors import ValidationError
from fabriclib.images.bundle.dependency_names import dependency_names


def resolve_packages(index, wanted):
    """Purpose: everything a host with nothing installed needs to install `wanted` (decision 2.1.14.16): the
             closure over Pre-Depends and Depends, the first alternative that exists (or a package providing it),
             from an archive index. The host's apt then installs only what that host lacks, from the bundle's
             local source; carrying a little more than one host needs is the price of not knowing its packages.
    Inputs:  index — dict {name: stanza dict (Package, Version, Filename, Size, SHA256, Depends, Pre-Depends,
             Provides)}, the newest version of each; wanted — list of package names.
    Returns: list of stanzas, sorted by package name.
    Fails:   ValidationError naming a wanted package, or a dependency, that nothing in the index satisfies.
    Feeds:   fetch_ubuntu."""
    provides = {}
    for name, st in index.items():
        for alts in dependency_names(st.get("Provides")):
            provides.setdefault(alts[0], []).append(name)
    chosen, todo = {}, [[w] for w in wanted]
    while todo:
        alts = todo.pop()
        if any(a in chosen for a in alts):
            continue
        pick = next((a for a in alts if a in index), None)
        if pick is None:
            pick = next((sorted(provides[a])[0] for a in alts if a in provides), None)
        if pick is None:
            raise ValidationError(f"no package in the Ubuntu archive provides {' | '.join(alts)}")
        if pick in chosen:
            continue
        chosen[pick] = index[pick]
        for field in ("Pre-Depends", "Depends"):
            todo.extend(dependency_names(index[pick].get(field)))
    return [chosen[k] for k in sorted(chosen)]
