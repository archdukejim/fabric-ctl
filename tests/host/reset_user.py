"""Put a person back to their first sign-in on a real install (tests/host, tests/sandbox): a new one-time password in
the domain (must be changed at the next sign-in), TOTP removed and sessions ended in Keycloak — fabric's own
reset_sign_in. The password goes to a file (0600), never to the screen or a command line.
    python3 reset_user.py <user> <password file>         (as root on the fabric host)
"""
import os
import sys

import yaml

sys.path.insert(0, "/opt/fabric/lib")
from fabriclib.directory.reset_sign_in import reset_sign_in  # noqa: E402

if len(sys.argv) != 3:
    sys.exit(__doc__)
user, out = sys.argv[1:3]
v = yaml.safe_load(open("/opt/fabric/config/vars.yaml"))
password = reset_sign_in(v, "test", user, caller=None, source="test")
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(password + "\n")
print(f"{user}: reset (one-time password in {out})")
