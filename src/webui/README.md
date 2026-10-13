# webui

**fabric-ctl** (*web control*): the control-plane web UI. It runs in its own
unprivileged container (`fabric-web`) and holds no power: every action is a
request to `fabric-agent` over a unix socket, carrying the signed-in person's
ID token, and `fabric-agent` checks it against their permissions. Installed by
the package as `/usr/lib/fabricctl/fabric/lib/webui/` (the Dockerfile and
`.dockerignore` go to `fabric/jinja/webui/build/`; see `packaging/deb/`).
Setup copies that build folder plus this app (as `app/`) into
`<deploy_base_dir>/webui/build/` and builds `fabric/web:local` from it.

| Path | What |
|---|---|
| `server.py` | Entry point of the production app behind nginx on a unix socket (the container's ENTRYPOINT): loads the config, starts the server |
| `handler.py` | One request: the security gates (client certificate from the Step-CA intermediate, Keycloak session bound to it, CSRF and Origin), routing, error pages; the response headers (strict CSP) |
| `app_state.py` | Shared state: config, the OIDC client, the expected certificate issuer, in-memory sessions and pending sign-ins |
| `constants.py` | Cookie names, body limit, sign-in and step-up timeouts |
| [security/](security/) | The certificate gate and the token's fabric permissions |
| [session/](session/) | The session bound to the certificate, renewal, the Keycloak sign-in, the page context |
| [httpio/](httpio/) | Reading forms, uploads and cookies; Set-Cookie headers |
| [routes/](routes/) | Every page and action |
| [views/](views/) | Every page's rendering; [templates/](../../templates/webui-app/) and [static/](../../static/webui-app/) hold the HTML and the stylesheet |
| [agentclient/](agentclient/) | The fabric-agent API client: one file per agent route |
| `oidc.py` | Keycloak OpenID Connect: authorization code flow with PKCE, token refresh, logout URL, ID token verification (RS256 against the realm JWKS; also used by `fabric-agent`) |
| `tlsclient.py` | HTTPS client that reaches a service by container IP but verifies its certificate for the public hostname against the fabric root CA only (also used by fabricctl's Keycloak code) |
| `devserver.py` | Dev preview: the real pages with sample data, no sign-in, nothing saved; a separate entry point, never in production ([devpreview/](devpreview/)) |
| `Dockerfile` | The image: Python 3, Jinja2, openssl and tini on the digest-pinned Debian base given by the compose file; runs `server.py` as the non-root `webui` user |
| `.dockerignore` | Keeps `__pycache__` and `*.pyc` out of the image |
| `__init__.py` | Empty; makes `webui` a package (`from webui import views`) |
