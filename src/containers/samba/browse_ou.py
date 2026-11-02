import ldb

from may_hold import kinds_held
from ou_paths import fixed_dns
import paths

# the containers a tree shows, as RSAT does by default (not those AD marks for its advanced view)
NODE = "(&(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain))" \
       "(!(showInAdvancedViewOnly=TRUE)))"
ATTRS = ["objectClass", "name", "sAMAccountName", "description", "userAccountControl", "objectCategory"]
DISABLED = 2                                     # userAccountControl: ACCOUNTDISABLE
FOUND_MAX = 200                                  # a search of the whole domain answers at most this many


def _part(rdn):
    """Purpose: an RDN's name ("OU=staff" -> "staff").
    Inputs:  rdn — str.
    Returns: str.
    Fails:   never.
    Feeds:   _path, browse_ou."""
    return rdn.split("=", 1)[1] if "=" in rdn else rdn


def _path(samdb, dn):
    """Purpose: a container's path below the domain, top down, as the console names it ("people/staff", "Users").
    Inputs:  samdb — SamDB; dn — str, inside the domain (the domain itself gives "").
    Returns: str.
    Fails:   never.
    Feeds:   browse_ou."""
    if dn.lower() == str(samdb.domain_dn()).lower():
        return ""
    rel = paths.relative(samdb, dn)
    return "/".join(reversed([_part(p) for p in rel.split(",")]))


def _resolve(samdb, path):
    """Purpose: a container's DN from its path, one level at a time (an OU, an AD container or Builtin by its name).
    Inputs:  samdb — SamDB; path — "" (the domain) or "a/b".
    Returns: str, its DN.
    Fails:   ValueError "no OU <path>" when a part is not there.
    Feeds:   browse_ou."""
    dn = str(samdb.domain_dn())
    for part in [p for p in str(path or "").strip("/").split("/") if p]:
        esc = ldb.binary_encode(part)
        found = samdb.search(base=dn, scope=ldb.SCOPE_ONELEVEL, attrs=["dn"],
                             expression=f"(&{NODE}(|(ou={esc})(cn={esc})))")
        if not found:
            raise ValueError(f"no OU {path}")
        dn = str(found[0].dn)
    return dn


def _kind(msg, services):
    """Purpose: an object's kind as the tree shows it.
    Inputs:  msg — ldb.Message (objectClass, objectCategory); services — OU=service-accounts' DN, lower case.
    Returns: "ou", "container", "machine", "person", "service account", "group", "contact" or "other".
    Fails:   never.
    Feeds:   _row."""
    classes = {str(c).lower() for c in msg.get("objectClass", [])}
    if "organizationalunit" in classes:
        return "ou"
    if "container" in classes or "builtindomain" in classes:
        return "container"
    if "computer" in classes:
        return "machine"
    if "group" in classes:
        return "group"
    if "contact" in classes:
        return "contact"
    if "user" in classes:
        return "service account" if str(msg.dn).lower().endswith("," + services) else "person"
    return "other"


def _row(samdb, msg, services):
    """Purpose: one object as the tree's contents list it.
    Inputs:  samdb — SamDB; msg — ldb.Message (ATTRS); services — OU=service-accounts' DN, lower case.
    Returns: {"kind", "name", "dn", "at" (its container's path), "description", "disabled"}.
    Fails:   never.
    Feeds:   browse_ou."""
    kind = _kind(msg, services)
    account = str(msg.get("sAMAccountName", [""])[0])
    name = account.rstrip("$").lower() if kind == "machine" else account or str(msg.get("name", [""])[0])
    dn = str(msg.dn)
    return {"kind": kind, "name": name, "dn": dn, "at": _path(samdb, dn.split(",", 1)[1]),
            "description": str(msg.get("description", [""])[0]),
            "disabled": bool(int(str(msg.get("userAccountControl", ["0"])[0])) & DISABLED)}


def browse_ou(samdb, lp, site, ou="", q="", whole=False, internal=False):
    """Purpose: the directory browser (manual 1.8.8.4): the tree opened to one OU (each level's child OUs and AD's
             containers, one-level searches only), that OU's contents (every object in it, sorted by kind then name),
             or a search of its contents or of the whole domain; fabric's fixed OUs marked, the grants' computed
             groups' OU and its groups left out unless asked for (1.8.8.3); each OU with the kinds a move or Create
             in... may put there (may_hold.kinds_held).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); ou — the OU's path ("" for
             the domain); q — text to find (name, account or description); whole — bool, search the whole domain
             (q needed, at least 2 characters); internal — bool, show the computed groups.
    Returns: {"ou", "levels": [{"path", "children": [{"name", "path", "kind": "ou"|"container", "fabric": bool,
             "kinds": [...]}]}] (the domain first, then each OU on the way), "contents": [rows], "found": bool (the
             search hit its limit), "kinds": the opened OU's}.
    Fails:   ValueError: no such OU, a whole-domain search without 2 characters; ldb.LdbError from a search.
    Feeds:   directory_ops (op "browse_ou")."""
    path = str(ou or "").strip("/")
    target = _resolve(samdb, path)
    fixed = fixed_dns(samdb)
    hidden = paths.computed_groups_dn(samdb).lower()
    services = paths.folder_dn(samdb, "service-accounts").lower()
    levels, at = [], str(samdb.domain_dn())
    for depth in range(len([p for p in path.split("/") if p]) + 1):
        children = []
        for c in samdb.search(base=at, scope=ldb.SCOPE_ONELEVEL, expression=NODE, attrs=["objectClass", "name"]):
            cdn = str(c.dn)
            if cdn.lower() == hidden and not internal:
                continue
            cpath = _path(samdb, cdn)
            is_ou = "organizationalunit" in {str(x).lower() for x in c.get("objectClass", [])}
            children.append({"name": _part(cdn.split(",", 1)[0]), "path": cpath,
                             "kind": "ou" if is_ou else "container", "fabric": cdn.lower() in fixed,
                             "kinds": kinds_held(samdb, cdn, cpath) if is_ou else []})
        levels.append({"path": _path(samdb, at), "children": sorted(children, key=lambda x: x["name"].lower())})
        parts = [p for p in path.split("/") if p]
        if depth < len(parts):
            at = _resolve(samdb, "/".join(parts[:depth + 1]))
    text = str(q or "").strip()
    if whole:
        if len(text) < 2:
            raise ValueError("a search of the whole domain needs at least 2 characters")
        esc = ldb.binary_encode(text)
        found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=ATTRS,
                             expression=f"(&(|(objectClass=user)(objectClass=group)(objectClass=contact)"
                                        f"(objectClass=organizationalUnit))(|(name=*{esc}*)(sAMAccountName=*{esc}*)"
                                        f"(description=*{esc}*)))")
        rows = [_row(samdb, m, services) for m in found
                if internal or not str(m.dn).lower().endswith("," + hidden)][:FOUND_MAX]
        full = len(found) > FOUND_MAX
    else:
        rows = [_row(samdb, m, services) for m in samdb.search(base=target, scope=ldb.SCOPE_ONELEVEL, attrs=ATTRS)
                if internal or str(m.dn).lower() != hidden]
        if text:
            low = text.lower()
            rows = [r for r in rows if low in r["name"].lower() or low in r["description"].lower()]
        full = False
    order = {"ou": 0, "container": 0, "person": 1, "service account": 2, "group": 3, "machine": 4, "contact": 5}
    rows.sort(key=lambda r: (order.get(r["kind"], 9), r["name"].lower()))
    return {"ou": path, "levels": levels, "contents": rows, "found": full,
            "kinds": kinds_held(samdb, target, path) if path else []}
