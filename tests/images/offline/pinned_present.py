"""Inside the offline box (tests/images/offline.sh): every image the installed package's lock pins (that it has
published) is known to Docker by that pinned ref. Prints the missing ones; exit 1 when any is."""
import subprocess
import sys

sys.path.insert(0, "/usr/lib/fabricctl/fabric/lib")
from fabriclib.images.bundle.bundle_images import bundle_images  # noqa: E402

missing = [e["ref"] for e in bundle_images("/usr/lib/fabricctl/fabric").values()
           if e["ref"] and subprocess.run(["docker", "image", "inspect", e["ref"]], capture_output=True).returncode]
print("missing:", missing)
sys.exit(1 if missing else 0)
