import ldb
from samba.dsdb import GTYPE_DISTRIBUTION_GLOBAL_GROUP

import paths


def save_role(samdb, lp, site, name, description, permissions, vlan, priority, new):
    """Purpose: a device role in AD (manual 1.6.3.5): what it grants its devices, an optional VLAN, a priority (the
             lower number wins). A role is a distribution group (never in anyone's sign-in token) with fabric's
             `fabricRole` class, named `role-<name>`; a new one goes in the domain's OU=device-roles (1.6.13.2,
             2.1.6.80; an admin's folder below it is searched too). Fields are checked by fabric first.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: roles are the domain's);
             name — the role's name; description — str; permissions — list; vlan — int or None; priority — int;
             new — bool: add (else replace the role wherever it lives under OU=device-roles).
    Returns: {"name"}.
    Fails:   ldb.LdbError ERR_ENTRY_ALREADY_EXISTS (add), ERR_NO_SUCH_OBJECT (replace), ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (ops "add_role", "update_role"); fabric's default roles."""
    values = {"description": description, "fabricPermission": list(permissions),
              "fabricVlan": str(vlan) if vlan else "", "fabricPriority": str(priority)}
    roles = paths.folder_dn(samdb, "device-roles")
    if new:
        samdb.newgroup(f"role-{name}", groupou=paths.relative(samdb, roles),
                       grouptype=GTYPE_DISTRIBUTION_GLOBAL_GROUP)
        samdb.rename(f"CN=role-{name},{roles}", f"CN={name},{roles}")
        dn = f"CN={name},{roles}"
        msg = ldb.Message(ldb.Dn(samdb, dn))
        msg["objectClass"] = ldb.MessageElement(["fabricRole"], ldb.FLAG_MOD_ADD, "objectClass")
        samdb.modify(msg)
    else:
        found = samdb.search(base=roles, scope=ldb.SCOPE_SUBTREE,
                             expression=f"(&(objectClass=fabricRole)(cn={ldb.binary_encode(name)}))", attrs=["dn"])
        if not found:
            raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT, f"no role {name}")
        dn = str(found[0].dn)
    msg = ldb.Message(ldb.Dn(samdb, dn))
    for k, val in values.items():
        msg[k] = ldb.MessageElement(val if isinstance(val, list) else ([val] if val else []), ldb.FLAG_MOD_REPLACE, k)
    samdb.modify(msg)
    return {"name": name}
