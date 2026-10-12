# jinja/nginx/www/landing

| File | What |
|---|---|
| `index.html.j2` | The landing page (extends `shared/base.html.j2`): links to the manual, the CA certificate page and the LDAP guide, plus the admin's `links` (link-vars.yaml) → `/opt/nginx/www/landing/index.html`, served at `http://<host_ip>/info/` and at `/` on `hostname_landing`, `<domain>` and the host's own name (manual 1.4.2.5); its links are relative |
