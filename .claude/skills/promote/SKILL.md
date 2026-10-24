---
name: promote
description: Promote fabric's tested release candidate to a full release: tag v<version> on the same commit as the last v<version>-rc.<n> (decision 2.1.1.40). Use when the owner runs /promote. Tags the images <version>, publishes the Release with the .deb and moves apt stable. Running it is the owner's request for the tag.
---

# /promote: the release candidate becomes the release

The step is [3.14.1.4](../../../docs/volume_3_installation/3.14.1-building-images.md#31414-publishing) step 7,
decision [2.1.1.40](../../../docs/volume_2_engineering_decisions/2.1.1-product.md). The owner running `/promote` is
the request for this tag (global Rule 8).

1. **Find the candidate**: `git fetch --tags origin`; `<version>` is `config/VERSION` on `origin/main`; the last rc tag
   is the highest `v<version>-rc.<n>`. None, or `v<version>` already exists: say so and stop.
2. **Check it**: its GitHub pre-release exists and its images carry `<version>-rc.<n>`. If main has moved past the rc
   tag, list the commits since; the release is the rc tag's commit, never a later one (say so to the owner).
3. **Tag the same commit** (annotated) and push the tag only:
   `git tag -a v<version> v<version>-rc.<n>^{} -m "<version>"`, then `git push origin v<version>`.
4. **Watch** the `package` and `images` runs for the tag. **Verify**: the Release `v<version>` (not a pre-release)
   carries `fabricctl_<version>_all.deb`; each `ghcr.io/archdukejim/open-fabric/<name>:<version>` resolves to the
   pinned digest; apt stable serves `<version>`
   (`https://archdukejim.github.io/fabric-ctl/dists/stable/main/binary-amd64/Packages` and `binary-arm64` list it).
5. **Report** what was released and verified. The production host is upgraded by the owner, never by the agent.
