import os

from fabriclib.samba.run_converge import run_converge


def prepare_site(v, site, networks, dc, dc_type, accounts, join_password, container="samba"):
    """Purpose: at the parent (the root, or a site with a writable DC: manual 1.9.8.14), before answering a join
             (manual 1.9.8.4, S8.1): converge the new site and its DC in the domain — the DC's record with the id
             range its name gives it (2.1.6.63; a read-only DC's too, and its cache group, 2.1.6.85), the site's group
             `site-<site>`, the DC's service accounts with the passwords it is given (2.1.6.82) and their rights, the
             site's networks and AD site, its GPOs (at OU=machines) — and make the temporary account its DC joins with
             (expiring in an hour). A site whose DC is in the domain already (one moving here) gets its AD site link
             to this parent only.
    Inputs:  v — the parent's vars (ad_password_policy, deploy_base_dir (the root CA), service_users); site — the new
             site's name; networks — its networks as the join request gives them ([{name, cidr, allow_overlap}]);
             dc — the joining DC's name (dc-NNNN, given by the parent); dc_type — "writable" or "rodc"; accounts —
             {kind: password} for agent, keycloak, radius (unused for a site moving here); join_password — the join
             account's password, or None for a site whose DC is in the domain already (one moving here: no join
             account, nothing of it changed but its link); container — the parent's DC.
    Returns: list of str, what changed.
    Fails:   ValidationError from run_converge (the DC not running, AD refusing); OSError reading the root CA;
             KeyError for a missing var.
    Feeds:   federation/accept_join."""
    root_ca = os.path.join(v["deploy_base_dir"], "stepca", "data", "certs", "root_ca.crt")
    nets = [{"name": n.get("name") or n["cidr"], "cidr": n["cidr"], "kind": n.get("kind") or "lan",
             "vlan": n.get("vlan"), "notes": n.get("notes") or "", "allow_overlap": n.get("allow_overlap") or ""}
            for n in networks]
    if join_password is None:            # a site moving here: its link to this parent, nothing else of it
        return run_converge({"site": site, "root": False, "parent": v["site_name"], "moving": True}, container)
    state = {"site": site, "dc": dc, "dc_type": dc_type, "root": False, "password_policy": v["ad_password_policy"],
             "networks": nets, "root_ca_pem": open(root_ca).read(), "groups": [],
             "accounts": {f"fabric-{kind}-{dc}": accounts[kind] for kind in ("agent", "keycloak", "radius")},
             "radius_gid": v["service_users"]["freeradius"]["gid"], "lan_profile": "",
             "parent": v["site_name"], "join_account": {"name": f"fabric-join-{site}", "password": join_password}}
    return run_converge(state, container)
