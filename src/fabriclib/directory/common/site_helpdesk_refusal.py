from fabriclib.keycloak.fabric_groups import fabric_groups

# a group whose name ends so holds a role at some site (2.1.9.13, 2.1.9.21): `<site>-admins`, `<site>-ou-admins`,
# `<site>-network-operators`, `<site>-helpdesk`, ... and fabric's own host and break-glass groups
ROLE_SUFFIXES = ("-admins", "-operators", "-helpdesk", "-auditors")
HOST_GROUPS = ("fabric-admins", "fabric-break-glass")


def site_helpdesk_refusal(v, person, what):
    """Purpose: why the site helpdesk (2.1.9.21, manual 1.6.8.2: a site's own admins, holding the console's
             `site:people:*` permissions only) may not change this person, or "" when it may: only a person of this
             site's own OU=people (not a sub-site's, a parent's or a sibling's: "own site", owner 2026-10-13), and never
             one who holds a role — a fabric group, the host admins, or any site's admin or role group (else a local
             admin could take over, or lock out, Central IT or another admin). AD keeps the same limits on its side
             (manual 1.6.3.18).
    Inputs:  v — fabric vars (site_name, fabric_groups'); person — get_person's {"uid", "dn", "groups"}; what — str,
             the change for the message ("reset their sign-in").
    Returns: str, the refusal ("" when allowed).
    Fails:   KeyError for a person without uid, dn or groups.
    Feeds:   person_guard."""
    site = (v.get("site_name") or "").lower()
    rdns = [part.split("=", 1) for part in person["dn"].split(",")]
    own = (len(rdns) >= 3 and all(len(r) == 2 for r in rdns[:3]) and rdns[1][0].upper() == "OU"
           and rdns[1][1].lower() == "people" and rdns[2][0].upper() == "OU" and rdns[2][1].lower() == site)
    if not own:
        return (f"{person['uid']} is not a person of site {v.get('site_name')}: a site's helpdesk manages its own "
                "site's people only")
    privileged = fabric_groups(v)
    held = sorted(g for g in person["groups"] if g in privileged or g in HOST_GROUPS or g.endswith(ROLE_SUFFIXES))
    if held:
        return f"{person['uid']} holds a role ({', '.join(held)}): only Central IT can {what}"
    return ""
