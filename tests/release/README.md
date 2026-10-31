# tests/release

Checks of what a release publishes, run by hand from WSL (manual 3.14.1).

| File | What |
|---|---|
| `apt_key_test.sh` | The apt repository's `public.key` (the published one, or a file): one key, fingerprint `9946C724…E6E73230`, its primary user ID fabric-ctl's (2.1.3.5, 3.14.1.6), the old open-fabric one not primary and revoked. Fails on the published key until the owner's rename has been published |
