# src/webui/devpreview

The dev preview (`devserver.py`): the production routes and pages over in-memory sample data, every agent call answered in the process by a fake agent; no sign-in, nothing saved. Never part of the production server.

| File | What |
|---|---|
| `dev_handler.py` | One dev-preview request through the production routes (src/webui/routes) and pages, over in-memory sample data; no sign-in, no certificate, nothing saved. |
| `dev_state.py` | In-memory sample data; nothing leaves this process. |
| `fake_connection.py` | Stands in for the agent's unix-socket connection: every agent call is answered in this process by fake_agent. |
| `fake_agent.py` | The stand-in for fabric-agent: one /v1/ request answered from the sample data, with the agent's own permission check. |
| `fake_reads.py` | The fake agent's reads (GET /v1/…) from the sample data, in the agent's shapes. |
| `fake_dns.py` | The fake agent's DNS changes: zones, records, the landing page's links, TSIG keys. |
| `fake_groups.py` | The fake agent's groups: the list, a group's page, create, delete, managers, members. |
| `fake_ous.py` | The fake agent's OUs: the tree, create, rename, delete, refused as the DC refuses. |
| `fake_machines.py` | The fake agent's computers: the list, a computer's page, type, sites, folder, a keytab command. |
| `fake_directory.py` | The fake agent's directory changes: people, 802.1X devices and roles, machines, host groups, sudo rules, the password policy, Group Policy. |
| `fake_network.py` | The fake agent's network changes: DHCP, 802.1X, the DNS filter and its query log. |
| `fake_misc.py` | The fake agent's other changes: Apply, events, jobs, the PKI, the vault, sign-in security, the setup wizard. |
| `fake_pending.py` | The fake agent's Apply per page: the agent's own pending store over the sample data, its jobs done at once. |
| `fake_account.py` | The fake agent's My account: the person's own read, managed groups, the own password. |
| `fabric_rules.py` | fabriclib's real rules when the dev preview runs from a checkout (devserver.py puts src on the path); the webui image carries only src/webui/, so without them the preview shows sample data and skips the directory forms. |
| `sample_data.py` | The dev preview's sample data: what a small home install looks like (nothing here is real). |
| `sample_radius_guides.py` | The FreeRADIUS setup guides as fabric-agent fills them in, built from the sample RADIUS data and the dev preview's own throwaway CA (SAMPLE_ROOT_PEM). Sample only; nothing is read from a host. |
| `sample_result.py` | A fake PKI result for the sign/issue/convert result page, shaped like fabric-agent's reply. |
| `sample_settings.py` | The setup wizard's sample settings, plan and settings file |
| `__init__.py` | Empty; makes it a package |
