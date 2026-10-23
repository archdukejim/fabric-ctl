# tests/images/offline

The offline install test's box (`tests/images/offline.sh`, manual 1.14.4.8).

| File | What |
|---|---|
| `Dockerfile` | Ubuntu 24.04 with systemd and nothing fabric installs: the bundle brings fabricctl, Docker and the packages (1.14.4.10) |
| `bootstrap.sh` | Inside the box: fabricctl installed from the bundle's own packages, the manual's procedure (3.14.2.2, step 2) |
| `pinned_present.py` | Inside the box: every image the package's lock pins is known to Docker by its pinned ref |
