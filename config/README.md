# config

| File | What |
|---|---|
| `VERSION` | fabric's version (semantic versioning, decision 2.1.1.18) |
| `images.lock.yaml` | Every container image fabric runs, pinned by digest (decision 2.1.14.4, manual 1.14) |
| `link-vars-template.yaml` | The landing page's links, the starting point of an install's `link-vars.yaml` |
| `sigstore-trusted-root.json` | Sigstore's trusted root an offline host checks fabric's published images' signatures against (manual 1.14.4.6; `scripts/images/trusted_root.py` refreshes it) |
