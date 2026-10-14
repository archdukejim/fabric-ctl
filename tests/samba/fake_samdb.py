"""A stand-in for Samba's `ldb` module and a SamDB, for the container-free tests of the DC's own operations
(tests/samba/site_roles_test.py): a directory held in a dict, LDAP filters with &, |, !, = and * read the way the
operations write them, and the few writes they make (group members, adminDescription, a new group). The real DC runs
them in tests/samba/roles.py (decision 2.1.1.27: a stand-in only for pure logic)."""
import sys
import types

SCOPE_BASE, SCOPE_ONELEVEL, SCOPE_SUBTREE = 0, 1, 2
FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE = 1, 2, 3
ERR_NO_SUCH_OBJECT, ERR_INSUFFICIENT_ACCESS_RIGHTS = 32, 50


class LdbError(Exception):
    pass


class MessageElement(list):
    def __init__(self, values, flag, name):
        super().__init__(values if isinstance(values, list) else [values])
        self.flag, self.name = flag, name


class Message(dict):
    def __init__(self, dn=None):
        super().__init__()
        self.dn = dn

    @staticmethod
    def from_dict(samdb, d, flag):
        m = Message(d["dn"])
        for k, v in d.items():
            if k != "dn":
                m[k] = MessageElement(v if isinstance(v, list) else [v], flag, k)
        return m


def install():
    """Put this module in sys.modules as `ldb`, so the DC's operations import it."""
    mod = types.ModuleType("ldb")
    for name in ("SCOPE_BASE", "SCOPE_ONELEVEL", "SCOPE_SUBTREE", "FLAG_MOD_ADD", "FLAG_MOD_REPLACE",
                 "FLAG_MOD_DELETE", "ERR_NO_SUCH_OBJECT", "ERR_INSUFFICIENT_ACCESS_RIGHTS", "LdbError",
                 "MessageElement", "Message"):
        setattr(mod, name, globals()[name])
    mod.binary_encode = lambda s: s
    sys.modules["ldb"] = mod
    # the DC's security descriptor helpers and id allocator, as the operations use them: an owner per object ("_owner",
    # the creator's "SID-<name>"; the system's when fabric made it), a SID per name, a gid counter
    acl = types.ModuleType("acl_entries")
    acl.sid_of = lambda samdb, name: f"SID-{name}"
    acl.owner_of = lambda samdb, dn: samdb.objects[dn].get("_owner", ["SID-system"])[0]
    acl.schema_guid = lambda samdb, name: f"GUID-{name}"
    acl.ensure_aces = lambda samdb, entries: [f"{dn}: {ace}" for dn, ace in entries]     # every entry, as wanted
    acl.remove_aces = lambda samdb, entries: []
    sys.modules["acl_entries"] = acl
    ids = types.ModuleType("alloc_id")
    ids.alloc_id = lambda samdb, site_dn, kind="person": samdb.next_id()
    sys.modules["alloc_id"] = ids


class Entry:
    def __init__(self, dn, attrs):
        self.dn, self.attrs = dn, attrs

    def get(self, name, default=None):
        return self.attrs.get(name.lower(), default)

    def __getitem__(self, name):
        return self.attrs[name.lower()]

    def __contains__(self, name):
        return name.lower() in self.attrs


def _parse(f):
    """An LDAP filter as nested tuples: ("&"|"|", [..]), ("!", x), ("=", attr, value)."""
    f = f.strip()
    assert f[0] == "(" and f[-1] == ")", f
    body = f[1:-1]
    if body[0] in "&|!":
        parts, depth, start = [], 0, 1
        for i, c in enumerate(body[1:], 1):
            depth += c == "("
            depth -= c == ")"
            if depth == 0 and c == ")":
                parts.append(_parse(body[start:i + 1]))
                start = i + 1
        return ("!", parts[0]) if body[0] == "!" else (body[0], parts)
    attr, value = body.split("=", 1)
    chain = "1.2.840.113556.1.4.1941" in attr          # LDAP_MATCHING_RULE_IN_CHAIN: nested membership
    return ("=", attr.split(":")[0].lower() + ("@chain" if chain else ""), value)


def _match(node, entry):
    kind = node[0]
    if kind == "&":
        return all(_match(n, entry) for n in node[1])
    if kind == "|":
        return any(_match(n, entry) for n in node[1])
    if kind == "!":
        return not _match(node[1], entry)
    _, attr, value = node
    have = [str(x) for x in entry.attrs.get(attr, [])]
    if value == "*":
        return bool(have)
    v = value.lower()
    for h in (x.lower() for x in have):
        if v.startswith("*") and h.endswith(v[1:]) or v.endswith("*") and h.startswith(v[:-1]) or h == v:
            return True
    return False


class FakeSamDB:
    """A directory: {dn: {attr: [values]}}, attribute names lower-cased; objectClass, sAMAccountName, member, ..."""

    def __init__(self, base="DC=ad,DC=test"):
        self.base, self.objects, self.log = base, {}, []
        self.actor, self.ids = "SID-system", 2000

    def domain_dn(self):
        return self.base

    def add_entry(self, dn, **attrs):
        self.objects[dn] = {k.lower(): (v if isinstance(v, list) else [v]) for k, v in attrs.items()}

    def search(self, base, scope=SCOPE_SUBTREE, expression="(objectClass=*)", attrs=None):
        tree = _parse(expression)
        out = []
        virtual = self._memberships()
        for dn, a in self.objects.items():
            a = {**a, **virtual.get(dn, {})}
            low, b = dn.lower(), base.lower()
            inside = (low == b if scope == SCOPE_BASE else
                      low.endswith("," + b) and low[:-len(b) - 1].count(",") == 0 if scope == SCOPE_ONELEVEL else
                      low == b or low.endswith("," + b))
            if inside and _match(tree, Entry(dn, a)):
                out.append(Entry(dn, a))
        if scope == SCOPE_BASE and not out and base not in self.objects:
            raise LdbError(ERR_NO_SUCH_OBJECT, base)
        return out

    def _memberships(self):
        """memberOf (direct), and member / memberOf through nesting ("@chain"), per DN, computed from member."""
        direct = {dn: [m for m in a.get("member", [])] for dn, a in self.objects.items()}
        parents = {}
        for g, ms in direct.items():
            for m in ms:
                parents.setdefault(m, []).append(g)

        def closure(start, edges):
            seen, todo = [], list(edges.get(start, []))
            while todo:
                x = todo.pop()
                if x not in seen:
                    seen.append(x)
                    todo += edges.get(x, [])
            return seen
        out = {}
        for dn in self.objects:
            out[dn] = {"memberof": parents.get(dn, []), "memberof@chain": closure(dn, parents),
                       "member@chain": closure(dn, direct)}
            if dn.upper().startswith("CN=") and "cn" not in self.objects[dn]:      # AD's cn, the DN's first value
                out[dn]["cn"] = [dn.split(",", 1)[0][3:]]
        return out

    def get_domain_sid(self):
        return "S-1-5-21-1"

    def rename(self, old, new):
        self.objects[new] = self.objects.pop(old)
        for a in self.objects.values():
            if "member" in a:
                a["member"] = [new if m.lower() == old.lower() else m for m in a["member"]]
        self.log.append(("rename", old, new))

    def _by_name(self, name):
        found = [dn for dn, a in self.objects.items() if name.lower() in [x.lower() for x in a.get("samaccountname", [])]]
        return found[0]

    def add_remove_group_members(self, group, members, add_members_operation=True):
        g = self.objects[self._by_name(group)]
        for m in members:
            dn = self._by_name(m)
            have = g.setdefault("member", [])
            if add_members_operation and dn not in have:
                have.append(dn)
            elif not add_members_operation:
                g["member"] = [x for x in have if x.lower() != dn.lower()]
        self.log.append(("members", group, tuple(members), add_members_operation))

    def modify(self, msg):
        a = self.objects[str(msg.dn)]
        for name, el in msg.items():
            if el.flag == FLAG_MOD_DELETE:
                a.pop(name.lower(), None)
            elif el.flag == FLAG_MOD_ADD:
                a.setdefault(name.lower(), []).extend(el)
            else:
                a[name.lower()] = list(el)
        self.log.append(("modify", str(msg.dn), tuple(sorted(msg))))

    def newgroup(self, name, groupou=None, description=None):
        dn = f"CN={name},{groupou},{self.base}"
        self.add_entry(dn, objectClass=["top", "group"], sAMAccountName=name, cn=name, _owner=self.actor,
                       **({"description": description} if description else {}))
        self.log.append(("newgroup", name))

    def delete(self, dn):
        del self.objects[dn]
        self.log.append(("delete", dn))

    def next_id(self):
        self.ids += 1
        return self.ids
