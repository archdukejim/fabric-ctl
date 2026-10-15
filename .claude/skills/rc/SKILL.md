---
name: rc
description: Build fabric's release candidate on rc/<version> and open the pull request to main (decision 2.1.1.40). Use when the owner runs /rc or asks for a release candidate. Bumps the version, publishes and pins the images, runs every suite, the sandbox, the image-update test, the test-Pi upgrade test and the rehearsal of every setup route, fixes what they find, then opens the PR. Never merges.
---

# /rc: fabric's release candidate

The procedure is in the manual: [3.14.1.4](../../../docs/volume_3_installation/3.14.1-building-images.md#31414-publishing)
steps 1–5, decision [2.1.1.40](../../../docs/volume_2_engineering_decisions/2.1.1-product.md). Read both first, and the
release's row in the roadmap (1.1.4.6) for what it holds. These are the steps in order, with this repository's
commands. The global rules apply throughout (feature branch, explicit paths, docs with code, the gate before each commit).

Arguments: the version (e.g. `0.6.4`); without one, ask.

1. **Branch** `rc/<version>` from `origin/main` (or continue the existing one). Set `config/VERSION`, commit, push.
2. **Gate and local suites** (WSL): the docs and lint checks, then `sudo tests/run-all.sh` (every suite but the sandbox).
   A failure is fixed before going on.
3. **Publish the images**: `gh workflow run images.yml --repo archdukejim/open-fabric --ref rc/<version> -f publish=true`,
   watch it, read the run number. **Pin** from the commit it ran on:
   `python3 scripts/images/pin_published.py <version>-rc.<run number>`, then
   `python3 scripts/images/source_hash.py --check`; commit the lock.
4. **apt testing**: `gh workflow run package.yml --repo archdukejim/open-fabric --ref rc/<version> -f apt_testing=true`.
5. **The sandbox**, kept: `sudo env KEEP=1 tests/sandbox/run.sh`; then **the image-update test** on it:
   `sudo tests/images/update.sh --box fabric-sandbox` (refresh `tests/images/previous.yaml` first: the previous
   release's digests and one version back for each upstream image).
6. **The test Pi** (`tempuser@192.168.5.57`, key `~/.ssh/fabric-test_ed25519`; **never the production host**).
   **Ask the owner before wiping it.** Then the upgrade test from the previous release
   (`tests/host/upgrade.sh`, `FROM=<previous>`, `TO_SUITE=testing`, no answers given ahead), and the host suite on a
   fresh install (purge first: `APT_SUITE=testing tests/host/run.sh`).
   **The rehearsal, before the owner tests** (3.14.1.4 step 4, 2.1.1.54): every setup route on a clean Pi from apt
   testing — unattended (`tests/host/run.sh` above) and interactive, Guided then Advanced with every default left
   (`tests/host/installer.py`, after `apt install fabricctl` on the purged Pi) — then look as a user would: the landing
   page at `http://<host ip>/certs/` and the console at its name. Leave the Pi purged with only `fabricctl` installed
   for the owner's own install, which is acceptance, not discovery.
7. **Fix what they find**: each fix with its test and docs, through the gate, committed and pushed. Re-run what it
   touches (a new `.deb` to apt testing first when host code changed; images only when an image's sources did:
   `source_hash.py --check` says). Record every run and finding in the release's notes.
8. **Open the pull request** `rc/<version>` → main with what is in it, what the tests found and the results; bind it
   in the app. **Never merge it**; tell the owner it is ready and that `/tag` follows the merge.
