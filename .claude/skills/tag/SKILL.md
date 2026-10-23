---
name: tag
description: Tag fabric's merged release candidate on main as v<version>-rc.<n> (decision 2.1.1.40). Use when the owner runs /tag after merging the rc pull request. Creates a GitHub pre-release with the .deb and tags the pinned images <version>-rc.<n>; leaves apt alone. Running it is the owner's request for the tag.
---

# /tag: tag the release candidate on main

The step is [3.14.1.4](../../../docs/volume_3_installation/3.14.1-building-images.md#31414-publishing) step 6,
decision [2.1.1.40](../../../docs/volume_2_engineering_decisions/2.1.1-product.md). The owner running `/tag` is the
request for this tag (global Rule 8); nothing else is tagged.

1. **Check the merge**: `git fetch origin`; the pull request `rc/<version>` → main is merged
   (`gh pr list --repo archdukejim/fabric-ctl --state merged --head rc/<version>`), and main's CI on the merge commit
   is green (`gh run list --repo archdukejim/fabric-ctl --branch main`). If not, say what is missing and stop.
2. **The tag**: `<version>` is `config/VERSION` on `origin/main`; `<n>` is one more than the highest existing
   `v<version>-rc.<n>` (`git tag -l "v<version>-rc.*"`), from 1.
3. **Tag the merge commit** (annotated) and push the tag only:
   `git tag -a v<version>-rc.<n> origin/main -m "<version> release candidate <n>"`, then
   `git push origin v<version>-rc.<n>`.
4. **Watch** the `package` and `images` runs for the tag. **Verify**: the GitHub Release `v<version>-rc.<n>` is a
   pre-release with `fabricctl_<version>_all.deb`; each image `ghcr.io/archdukejim/open-fabric/<name>:<version>-rc.<n>`
   resolves to the digest `config/images.lock.yaml` pins (`docker buildx imagetools inspect`); apt stable still
   serves the previous release.
5. **Report**: the tag, its commit, what was verified, and how to test-install it (the pre-release's `.deb`:
   `sudo apt install ./fabricctl_<version>_all.deb`, then `sudo fabricctl setup`). A fix found by a test install goes
   back through `/rc`; `/promote` follows a good test.
