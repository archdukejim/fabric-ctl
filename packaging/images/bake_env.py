"""Print the build inputs of fabric's own images (decision 2.1.1.21, manual 3.14.1) as KEY=VALUE lines for
packaging/docker-bake.hcl: the digest-pinned bases and Kea's pinned package, read from config/images.lock.yaml
(the same lock a host builds from). Usage: python3 packaging/images/bake_env.py >> "$GITHUB_ENV", or
`set -a; . <(python3 packaging/images/bake_env.py); set +a` in a shell."""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.common.read_packages_lock import read_packages_lock  # noqa: E402


def bake_env(config_dir):
    """Purpose: the variables docker-bake.hcl needs, from the lock files.
    Inputs:  config_dir — str, the folder holding images.lock.yaml (the checkout's config/).
    Returns: dict {variable: value}: BASE_<image> for each base fabric builds FROM (golang: Step-CA's certificate
             reader), KEA_* for Kea's package.
    Fails:   KeyError if the lock lacks one of those bases or Kea's package; yaml.YAMLError on an invalid lock.
    Feeds:   this script's output (the images workflow and the manual's build procedure)."""
    images, kea = read_images_lock(config_dir), read_packages_lock(config_dir)["kea"]
    env = {f"BASE_{name.upper()}": images[name]["ref"] for name in ("debian", "stepca", "keycloak", "golang")}
    env.update(KEA_VERSION=kea["version"], KEA_REPO=kea["repo"], KEA_SUITE=kea["suite"],
               KEA_KEY_URL=kea["key_url"], KEA_KEY_FINGERPRINT=kea["key_fingerprint"])
    return env


if __name__ == "__main__":
    for key, value in bake_env(os.path.join(REPO, "config")).items():
        print(f"{key}={value}")
