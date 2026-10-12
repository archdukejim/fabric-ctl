# jinja/nginx/www/certs

Rendered by `deploy.py` to `/opt/nginx/www/certs/`; the CA certificate files
beside them are published by `fabriclib/pki/publish_ca_certs.py`. Served at
`http(s)://info.<domain>/certs/` (`hostname_landing`) and `http://<host_ip>/certs/` (manual 1.5.1.5).

| File | What |
|---|---|
| `index.html.j2` | The certificate page: download the fabric root/intermediate CA and install it per platform → `index.html` |
| `install-certs.sh.j2` | Downloads the CA certificates and installs them into the system trust store → `install-certs-<domain_file>.sh` |
| `install-all-ubuntu.sh.j2` | Runs the system, Firefox, Chrome and Python installs on Ubuntu → `install-all-<domain_file>.sh` |
| `install-firefox-ubuntu.sh.j2` | Adds the root CA to Firefox profiles (NSS) → `install-firefox-<domain_file>.sh` |
| `install-chrome-ubuntu.sh.j2` | Adds the root CA to Chrome/Chromium's NSS database → `install-chrome-<domain_file>.sh` |
| `install-python-ubuntu.sh.j2` | Makes Python (certifi/requests) trust the root CA → `install-python-<domain_file>.sh` |
| `join-linux.sh.j2` | Joins an Ubuntu machine to the domain: pins the root CA by fingerprint, adcli, SSSD (manual 1.6.7) → `join-linux.sh` |
