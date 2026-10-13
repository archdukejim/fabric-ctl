# tests/webui

| File | What |
|---|---|
| `test_container.py` | The web UI container against a mock Keycloak (real RS256 tokens) and the real fabric-agent: sign-in gates, sessions and token renewal, CSRF, the DNS, Step-CA, TSIG and OpenBao pages (step-up for vault changes), RBAC in pages and in the agent, isolation |
| `test_devserver.py` | The dev preview: every page renders with sample data (the DHCP options page with a target's sources included), edits in memory, `--as` a role bundle; production has no dev switch |
