# fabriclib/federation/common

Helpers shared by the federation operations.

| File | What |
|---|---|
| `federation_lock.py` | Exclusive lock around invitations and the site registry (CLI and endpoint) |
| `load_registry.py` | This install's federation record (`config/federation.yaml`): joined sites, its upstream |
| `save_registry.py` | Write the federation record atomically (0640) |
| `fetch_pinned_root.py` | Joining node: the upstream's root over plain HTTP, accepted only if it matches the invitation's fingerprint |
| `post_upstream.py` | Joining node: POST to the upstream's endpoint over TLS verified against the pinned root, by address with the endpoint's name |
| `signing_capacity.py` | How this install signs a site's CA (root key, or its own CA as a parent) and how deep that site may nest |
| `site_name_problem.py` | Why a name cannot be a site's: not one host-name label, or one of the organisation's top-level OUs |
| `is_root_site.py` | Whether this install is the root site (no upstream): it holds the organisation's part of the domain |
| `sites_shown.py` | Which sites' address plans this install shows: every site at the top, else itself and the sites below it (2.1.9.22) |
| `visible_plan.py` | The address plan and its overlaps for the sites shown; an overlap with a site not shown counted, never named (2.1.9.22) |
