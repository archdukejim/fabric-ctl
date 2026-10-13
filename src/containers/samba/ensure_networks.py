import ldb

import paths

# what a fabricNetwork entry holds, from a site_networks item (manual 1.10.2.8)
FIELDS = {"fabricCidr": "cidr", "fabricNetworkKind": "kind", "fabricVlan": "vlan", "description": "notes",
          "fabricAllowOverlap": "allow_overlap"}


def ensure_networks(samdb, site, networks):
    """Purpose: the site's networks as `fabricNetwork` entries in its OU=networks (manual 1.10.2.8, S4.1), the address
             plan every site reads: added, changed to match, and removed when the site no longer has them. A subnet
             of the address manager's plan (an entry with the fabricSubnet class, 1.10.4.13) is the plan's own:
             never changed or removed here, and a network of the same name or network is left to it.
    Inputs:  samdb — SamDB (as the system); site — str; networks — site_networks' list of {name, cidr, kind, vlan,
             notes, allow_overlap}.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError for a change AD refuses (e.g. OU=networks missing: ensure_layout makes it first).
    Feeds:   converge."""
    base = f"OU=networks,{paths.site_dn(samdb, site)}"
    have, planned = {}, set()
    for m in samdb.search(base=base, scope=ldb.SCOPE_ONELEVEL, expression="(objectClass=fabricNetwork)",
                          attrs=["cn", "objectClass", "fabricSite", *FIELDS]):
        if "fabricSubnet" in [str(c) for c in m["objectClass"]]:
            planned |= {str(m["cn"][0]).lower(), str(m.get("fabricCidr", idx=0) or "")}
        else:
            have[str(m["cn"][0]).lower()] = m
    done = []
    for n in networks:
        if n["name"].lower() in planned or n["cidr"] in planned:
            continue
        want = {attr: str(n.get(key) or "") for attr, key in FIELDS.items()}
        want["fabricSite"] = site
        old = have.pop(n["name"].lower(), None)
        if old is None:
            dn = ldb.Dn(samdb, f"CN=network,{base}")
            dn.set_component(0, "CN", n["name"])         # escaped, whatever the name holds
            samdb.add({"dn": dn, "objectClass": "fabricNetwork", **{k: val for k, val in want.items() if val}})
            done.append(f"network {n['name']} added")
            continue
        msg = ldb.Message(old.dn)
        for attr, val in want.items():
            if str(old.get(attr, idx=0) or "") != val:
                msg[attr] = ldb.MessageElement([val] if val else [], ldb.FLAG_MOD_REPLACE, attr)
        if len(msg) > 0:
            samdb.modify(msg)
            done.append(f"network {n['name']} changed")
    for old in have.values():
        samdb.delete(old.dn)
        done.append(f"network {old['cn'][0]} removed")
    return done
