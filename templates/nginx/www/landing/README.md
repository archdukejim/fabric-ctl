# jinja/nginx/www/landing

| File | What |
|---|---|
| `index.html.j2` | The landing page (extends `shared/base.html.j2`): links to the manual, the CA certificate page and the LDAP guide, plus the admin's `links` (link-vars.yaml) → `/opt/nginx/www/landing/index.html`, served at `http://<host_ip>/info/` and at `/` on its landing names: the host's own name, `<domain>` and the zone's aliases of the host (manual 1.4.2.5, 1.4.2.6); its links are relative |
