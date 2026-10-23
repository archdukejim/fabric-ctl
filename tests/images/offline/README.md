# tests/images/offline

The offline install test's box (`tests/images/offline.sh`, manual 1.14.4.8).

| File | What |
|---|---|
| `Dockerfile` | Ubuntu 24.04 with systemd and the Ubuntu packages fabric installs (bundles do not carry them yet, 2.1.14.16) |
| `pinned_present.py` | Inside the box: every image the package's lock pins is known to Docker by its pinned ref |
