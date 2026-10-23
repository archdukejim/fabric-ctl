import ldb

import paths

# what a fabricNetwork entry holds, from a site_networks item (manual 1.10.2.8)
FIELDS = {"fabricCidr": "cidr", "fabricNetworkKind": "kind", "fabricVlan": "vlan", "description": "notes",
          "fabricAllowOverlap": "allow_overlap"}


def network_cn(site, name):
    """Purpose: a network's entry name in the domain's OU=networks: its site and its name, so two sites' networks of
             one name never meet (2.1.6.80).
    Inputs:  site — str; name — the network's name.
    Returns: str "<site>/<name>" (escaped where the DN is built).
    Fails:   never.
    Feeds:   ensure_networks, read_networks (which splits it at the first "/")."""
    return f"{site}/{name}"


def ensure_networks(samdb, site, networks):
    """Purpose: the site's networks as `fabricNetwork` entries in the domain's OU=networks (manual 1.10.2.8, S4.1;
             1.6.13.2), the address plan every site reads: added, changed to match, and removed when the site no
             longer has them. Only this site's entries (fabricSite) are touched, and never one of the address
             manager's subnets (the `fabricSubnet` class, manual 1.10.4.33): convergence neither changes nor removes
             one, nor writes a network of a plan subnet's name or network.
    Inputs:  samdb — SamDB (as the system); site — str; networks — site_networks' list of {name, cidr, kind, vlan,
             notes, allow_overlap}.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError for a change AD refuses (e.g. OU=networks missing: ensure_layout makes it first).
    Feeds:   converge."""
    base = paths.folder_dn(samdb, "networks")
    have, plan_names, plan_cidrs = {}, set(), set()
    for m in samdb.search(base=base, scope=ldb.SCOPE_ONELEVEL,
                          expression=f"(&(objectClass=fabricNetwork)(fabricSite={ldb.binary_encode(site)}))",
                          attrs=["cn", "objectClass", "fabricSite", *FIELDS]):
        if "fabricSubnet" in [str(c) for c in m["objectClass"]]:      # the plan's: fabric-agent's alone
            plan_names.add(str(m["cn"][0]).lower())
            plan_cidrs.add(str(m.get("fabricCidr", idx=0) or ""))
            continue
        have[str(m["cn"][0]).lower()] = m
    done = []
    for n in networks:
        if network_cn(site, n["name"]).lower() in plan_names or str(n.get("cidr") or "") in plan_cidrs:
            continue
        want = {attr: str(n.get(key) or "") for attr, key in FIELDS.items()}
        want["fabricSite"] = site
        old = have.pop(network_cn(site, n["name"]).lower(), None)
        if old is None:
            dn = ldb.Dn(samdb, f"CN=network,{base}")
            dn.set_component(0, "CN", network_cn(site, n["name"]))       # escaped, whatever the name holds
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
        done.append(f"network {str(old['cn'][0]).split('/', 1)[-1]} removed")
    return done
