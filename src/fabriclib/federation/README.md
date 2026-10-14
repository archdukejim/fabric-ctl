# fabriclib/federation

Sites joined into one fabric: an upstream that owns identity and the root CA, downstream sites with
their own local network (design [1.9.1](../../../docs/volume_1_description_and_architecture/1.9.1-sites.md#1911-status)).

| File | What |
|---|---|
| `constants.py` | The site-name, domain and base-DN rules, the invitation format and lifetime, the join body limit |
| `create_invitation.py` | Upstream: a one-time invitation for a new site (only a hash of its secret is kept; audited) |
| `list_invitations.py` | Upstream: the open invitations, without their secrets |
| `request_dc_type.py` | At a site above: ask a site below to change its DC type; the request in AD, a one-time change token (2.1.9.23) |
| `accept_dc_type.py` | At the site above (the endpoint's POST /v1/dc-type): the change token redeemed for the temporary join account (2.1.9.23) |
| `plan_dc_type_change.py` | At the site: what accepting a DC type change does, or why it may not (pure, 2.1.9.23) |
| `change_dc_type.py` | At the site: the DC type change carried out step by step, each recorded (2.1.9.23) |
| `read_change_token.py` | The change token from a file, stdin or a hidden prompt, never the command line (2.1.9.23) |
| `confirm_plan.py` | Show what a federation command will change and have the person type a word to go on (2.1.9.23, 2.1.6.58) |
| `site_below.py` | Whether a site sits below this one in the domain (its OU inside this site's) |
| `plan_rodc_lost.py` | What handling a site's lost read-only DC does, or why it may not (pure, 2.1.6.58) |
| `rodc_lost.py` | A site's read-only DC lost or stolen: the accounts it held listed, reset on confirmation, the DC removed, all recorded and audited (2.1.6.58) |
| `revoke_invitation.py` | Upstream: withdraw an open invitation (audited) |
| `accept_join.py` | Upstream: an invited site joins — check the invitation, sign the site's CA with the root key, record the site |
| `decode_invitation.py` | Joining node: read and check an invitation (no network) |
| `join_upstream.py` | Joining node: make the site CA request, pin the upstream's root, join over verified TLS, stage the CA, record the upstream |
| `relay_join.py` | On a relay node: pass a join that names it (`via`) on to its upstream and return the answer unchanged |
| `drop_relay.py` | On a site that joined through a relay: talk to the upstream directly from now on |
| `remove_site.py` | On a parent: forget a site that joined here, revoking its CA (2.1.5.10) |
| `reparent_site.py` | On a site: move under another parent with its invitation — new CA, Step-CA switched, certificates re-issued |
| `dns_links.py` | The DNS links to the sites next to this one (delegation, secondary zones, TSIG keys) for the BIND templates |
| `federation_status.py` | Standalone, upstream or site; the endpoint; joined sites; open invitations |
| `set_federation_endpoint.py` | Turn the federation endpoint on or off (certificate first) and apply |
| `deploy_federation_endpoint.py` | Deploy step: the `fabric-federation` unit and the socket directory nginx mounts (or their removal) |
| `site_networks.py` | This site's networks for the address plan: the LAN and every DHCP subnet (name, VLAN, notes, overlap reason) |
| `read_address_plan.py` | The address plan from the domain: every site's networks, written by convergence (1.10.2.8) |
| `network_conflicts.py` | Which of this site's networks overlap another site's (and whether a reason allows it) |
| `show_networks.py` | `fabricctl federation networks`: the plan and its overlaps |
| `run_federation_command.py` | `fabricctl federation status / enable / disable / invite / invitations / revoke / networks` |
| `common/` | Helpers shared by the operations above (see its README) |
| `next_id_block.py` | The uid/gid block a new site gets at its join: the next after every block handed out |
| `federation_overview.py` | The Federation tab: sites, replication, conflicts, limits, the address plan |
| `site_roles.py` | The roles granted at this site and the sites below it, from the domain (2.1.9.21) |
| `change_site_role.py` | Grant a role at a site below this one, or take it back (audited, 2.1.9.21) |
| `remake_site_group.py` | Make a site below's role group or `<site>-admins` again: one the site made itself, or a missing one (audited, 2.3.9.2.8) |
| `run_roles_command.py` | `fabricctl federation roles [<site>] / grant / revoke` |
