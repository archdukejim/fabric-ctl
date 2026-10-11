# tests/webui

| File | What |
|---|---|
| `test_container.py` | The web UI container against a mock Keycloak (real RS256 tokens) and the real fabric-agent: sign-in gates, sessions and token renewal, CSRF, the DNS, Step-CA, TSIG and OpenBao pages (step-up for vault changes); the Kea, DNS filter and FreeRADIUS forms saved to the real vars.yaml and secrets with each refusal named and nothing saved (the apply checked to fail here, so nothing is deployed and the host firewall is never touched); the agent's DHCP, DNS filter, 802.1X, vault and images routes; RBAC in pages and in the agent, isolation |
| `test_devserver.py` | The dev preview: every page renders with sample data, edits in memory, `--as` a role bundle; production has no dev switch |
