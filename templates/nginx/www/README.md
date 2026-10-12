# jinja/nginx/www

Static content, rendered or copied by `deploy.py` to `/opt/nginx/www/<folder>/`
(nginx-owned, 0644 files) and served by nginx from `/srv/www`.

| Folder | What |
|---|---|
| [certs/](certs/) | The certificate page and the CA install scripts (`info.<domain>/certs/`, `http://<host_ip>/certs/`) |
| [landing/](landing/) | The landing page (`/info/` on every name, `/` on `hostname_landing`, `<domain>` and the host's name: 1.4.2.5) linking every service |
| [manual/](manual/) | The manual viewer (`/manual/`): renders the repository's `docs/` (copied to `manual/docs/`) in the browser |
| [shared/](shared/) | The base page template and the stylesheet every page uses |
