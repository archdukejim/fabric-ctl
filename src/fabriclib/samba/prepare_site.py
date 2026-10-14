import os

from fabriclib.keycloak.fabric_groups import fabric_groups
from fabriclib.samba.run_converge import run_converge


def prepare_site(v, site, networks, id_block, accounts, join_password, container="samba"):
    """Purpose: at the parent (the root, or a site with a writable DC: manual 1.9.8.14), before answering a join
             (manual 1.9.8.4, S8.1): converge the new site in the domain, in the parent's OU —
             its OU and the OUs under it, its groups (`<site>-users`, `<site>-admins`), its service accounts with
             the passwords it is given, its ACLs, its id block, its networks and AD site, its sudo rule and GPOs — and
             make the temporary account its DC joins with (expiring in an hour).
    Inputs:  v — the parent's vars (ad_password_policy, deploy_base_dir (the root CA), webui_admin_group,
             service_users); site — the new site's name; networks — its networks as the join request gives them
             ([{name, cidr, allow_overlap}]); id_block — "first-last" (next_id_block); accounts — {kind: password} for
             agent, keycloak, radius (unused for a site moving here); join_password — the join account's password,
             or None for a site whose DC is in the domain already (one moving here: its OU moves, no join account,
             its service accounts untouched); container — the parent's DC.
    Returns: list of str, what changed.
    Fails:   ValidationError from run_converge (the DC not running, AD refusing); OSError reading the root CA;
             KeyError for a missing var.
    Feeds:   federation/accept_join."""
    root_ca = os.path.join(v["deploy_base_dir"], "stepca", "data", "certs", "root_ca.crt")
    nets = [{"name": n.get("name") or n["cidr"], "cidr": n["cidr"], "kind": n.get("kind") or "lan",
             "vlan": n.get("vlan"), "notes": n.get("notes") or "", "allow_overlap": n.get("allow_overlap") or ""}
            for n in networks]
    state = {"site": site, "root": False, "password_policy": v["ad_password_policy"], "networks": nets,
             "root_ca_pem": open(root_ca).read(), "id_range": id_block, "groups": [],
             "admin_group": v.get("webui_admin_group") or "admins",
             "privileged_groups": sorted(fabric_groups(v) | {"fabric-admins", "fabric-break-glass"}),
             # a site moving here keeps its service accounts and their passwords (convergence would reset them)
             "accounts": {} if join_password is None else
                         {f"fabric-{kind}-{site}": accounts[kind] for kind in ("agent", "keycloak", "radius")},
             "radius_gid": v["service_users"]["freeradius"]["gid"], "lan_profile": "",
             "parent": v["site_name"]}
    if join_password is not None:
        state["join_account"] = {"name": f"fabric-join-{site}", "password": join_password}
    else:                    # its GPOs belong to its own DC (S8.4): it rewrites them when it converges next
        state["moving"] = True
    return run_converge(state, container)
