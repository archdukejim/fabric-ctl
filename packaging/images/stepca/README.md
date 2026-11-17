# jinja/stepca/build

Build context of the local image `fabric/stepca:local`, copied (not rendered)
to `/opt/stepca/build/` by `deploy.py`; rebuilt when it changes or its base
differs (`fabriclib/images/needs_rebuild.py`).

| File | What |
|---|---|
| `Dockerfile` | Copies `/usr/local/bin/step-ca` on `BASE_IMAGE` (pinned `image_stepca`) to drop its cap_net_bind_service file capability, so it runs with no capabilities and no-new-privileges; labels `org.fabric.base` and `org.fabric.go`; adds `/usr/local/bin/fabric-certlist` from the reader stage |
| `reader/` | `fabric-certlist`, a small Go program built in a first stage on `GO_IMAGE` (pinned `image_golang`): lists the certificates in Step-CA's database, read from a copy (2.1.5.13); see its README |
| `.dockerignore` | Keeps `__pycache__` and `*.pyc` out of the build context |
