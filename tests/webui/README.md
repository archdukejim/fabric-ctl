# tests/webui

| File | What |
|---|---|
| `test_container.py` | The web UI container against a mock Keycloak (real RS256 tokens) and the real fabric-agent: sign-in gates, sessions and token renewal, CSRF, the DNS, Step-CA, TSIG and OpenBao pages (step-up for vault changes); the Kea, DNS filter and FreeRADIUS forms saved to the real vars.yaml and secrets with each refusal named and nothing saved (the apply checked to fail here, so nothing is deployed and the host firewall is never touched); the agent's DHCP, DNS filter, 802.1X, vault and images routes; RBAC in pages and in the agent, isolation |
| `test_devserver.py` | The dev preview (the production routes over a fake agent): every page renders with sample data, edits in memory; per bundle (`--as`) the navigation's entries and every page opened with its permission and refused without it; the old addresses redirected; no script or inline style; a form's message shown once, never from the address; production has no dev switch |
| `test_narrow.py` | Every console page at 375 px in headless Chromium (the test browser image, decision 2.1.8.15): nothing wider than the screen, nothing scrolling sideways inside a card |
| `narrow_probe.py` | Runs inside the test browser image: opens each page at a phone's width over Chromium's DevTools pipe and reports what is past the right edge |
