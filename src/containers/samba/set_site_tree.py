import re

import ldb

import paths
from ensure_site_record import MARK

# a console's address: https, a host name (or an address) and an optional port, nothing after it (2.1.8.30)
CONSOLE_RE = re.compile(r"^https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$")
SITE_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def set_site_tree(samdb, lp, site, name="", parent="", console=""):
    """Purpose: a site's place in the federation on its record (decision 2.1.8.30, manual 1.8.6.12): its parent site
             (`fabricParentSite`, none for the root) and its console's address (`fabricConsoleUrl`), through the
             auxiliary class `fabricSiteTree`; the record made when missing, as ensure_site_record makes it. Written
             by the parent when a site joins and kept by the site's own convergence (a read-only DC's site asks its
             writable partner, as run_op's server).
    Inputs:  samdb — SamDB (as the asking DC's fabric-agent); lp — LoadParm (unused); site — the asking site; name —
             the site whose record it is (default: the asking site); parent — its parent's name, "" for none;
             console — its console's address, "https://<host>[:<port>]", "" to leave it as it is.
    Returns: {"site", "changed": [what was set]}; nothing changed when it already held these.
    Fails:   ValueError for a site name, a parent's name or an address that is not one (before anything is written);
             ldb.LdbError from a change AD refuses (CN=sites missing: the domain has not converged).
    Feeds:   directory_ops (op "set_site_tree")."""
    name = (name or site).strip().lower()
    parent, console = (parent or "").strip().lower(), (console or "").strip().lower().rstrip("/")
    if not SITE_RE.match(name) or (parent and not SITE_RE.match(parent)) or parent == name:
        raise ValueError(f"not a site's name, or a site its own parent: {name!r}, {parent!r}")
    if console and not CONSOLE_RE.match(console):
        raise ValueError(f"not a console's address (https://<host>[:<port>]): {console!r}")
    dn = paths.site_record_dn(samdb, name)
    changed = []
    try:
        samdb.add({"dn": dn, "objectClass": "fabricSiteRecord", "description": MARK})
        changed.append("record")
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_ENTRY_ALREADY_EXISTS:
            raise
    have = samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                        attrs=["objectClass", "fabricParentSite", "fabricConsoleUrl"])[0]
    if "fabricSiteTree" not in [str(c) for c in have["objectClass"]]:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": str(dn), "objectClass": "fabricSiteTree"},
                                           ldb.FLAG_MOD_ADD))
    want = {"fabricParentSite": parent, **({"fabricConsoleUrl": console} if console else {})}
    for attr, value in want.items():
        now = str(have[attr][0]) if attr in have else ""
        if now == value:
            continue
        flag = ldb.FLAG_MOD_REPLACE if value else ldb.FLAG_MOD_DELETE
        msg = ldb.Message(dn)
        msg[attr] = ldb.MessageElement([value] if value else [], flag, attr)
        samdb.modify(msg)
        changed.append(attr)
    return {"site": name, "changed": changed}
