from fabriclib.common.errors import ValidationError
from fabriclib.directory.run_op import run_op


def write_site_place(v, secrets, name, parent, console, container="samba"):
    """Purpose: one site's place in the federation on its record in the domain (decision 2.1.8.30, manual 1.8.6.12):
             its parent and its console's address, written as this DC's fabric-agent (directory operation
             set_site_tree, so AD's ACLs apply). A site with a read-only DC writes at its writable partner
             (ad_join_server), as every change it makes.
    Inputs:  v — rendered vars (site_name, dc_name, ad_dc_type, ad_join_server); secrets — fabric's secrets
             (ad_agent_password); name — the site whose record it is; parent — its parent site ("" for the root);
             console — its console's address ("" to leave the recorded one); container — this site's DC.
    Returns: list of str, what changed ("site <name>: <attribute> set"), empty when the record already held it.
    Fails:   ValidationError from run_op (no DC here, the DC not reachable, a name or address refused).
    Feeds:   federation/accept_join (the parent, when a site joins), federation/keep_site_place (each convergence)."""
    server = None
    if v.get("ad_dc_type") == "rodc":
        server = str(v.get("ad_join_server") or "").strip()
        if not server:
            raise ValidationError("this site's DC is read-only and no writable DC is set (ad_join_server)")
    out = run_op(v, secrets, "set_site_tree", {"name": name, "parent": parent, "console": console},
                 container=container, server=server)
    return [f"site {out['site']}: {what} set" for what in out.get("changed") or []]
