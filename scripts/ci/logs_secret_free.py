"""CI: before the suites' logs are kept as artifacts (3.1.2.4), make sure none holds a secret the run made.
    sudo python3 scripts/ci/logs_secret_free.py /tmp/fabric-tests"""
import os
import sys

import yaml

SECRET_NAMES = ("pw", "pass", "secret", "token", "chpasswd")     # files the suites keep a password or key in
SECRET_KEYS = ("secret", "password", "passphrase", "token", "key")


def _values(node):
    """Purpose: every string under a YAML key that names a secret, at any depth.
    Inputs:  node — parsed YAML.
    Returns: list of str.
    Fails:   never.
    Feeds:   secrets_in."""
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str) and any(s in str(k).lower() for s in SECRET_KEYS):
                out.append(v)
            else:
                out += _values(v)
    elif isinstance(node, list):
        for v in node:
            out += _values(v)
    return out


def secrets_in(root):
    """Purpose: the secrets a test run left in its folder: the contents of its password and key files, and the values
             of secret keys in its YAML files (an embedded TSIG secret, for one).
    Inputs:  root — the run's folder (/tmp/fabric-tests).
    Returns: set of str, 8 characters or more (shorter ones would match by chance).
    Fails:   never for a file it cannot read or parse (skipped).
    Feeds:   main."""
    found = set()
    for folder, _, files in os.walk(root):
        for name in files:
            path = os.path.join(folder, name)
            if name.endswith(".log") or os.path.getsize(path) > 65536:
                continue
            try:
                text = open(path, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                continue
            if any(s in name.lower() for s in SECRET_NAMES) and not name.endswith((".py", ".sh")):
                found.update(line.split(":", 1)[-1].strip() for line in text.splitlines())
            elif name.endswith((".yaml", ".yml")):
                try:
                    found.update(_values(yaml.safe_load(text)))
                except yaml.YAMLError:
                    pass
    return {s for s in found if len(s) >= 8}


def main(root):
    """Purpose: remove every log that holds one of the run's secrets, so the upload never carries it, and fail.
    Inputs:  root — the run's folder.
    Returns: 0 when no log holds a secret, else 1 (each such log named and removed; the secret never printed).
    Fails:   OSError removing a log.
    Feeds:   .github/workflows/suites.yml (before *Keep the logs*)."""
    secrets = secrets_in(root)
    bad = []
    for folder, _, files in os.walk(root):
        for name in files:
            if not name.endswith(".log"):
                continue
            path = os.path.join(folder, name)
            text = open(path, encoding="utf-8", errors="replace").read()
            if any(s in text for s in secrets):
                bad.append(path)
                os.remove(path)
    for path in bad:
        print(f"::error::{path} held a secret of this run: removed, not kept")
    print(f"{len(secrets)} secret(s) of the run checked against the logs; {len(bad)} log(s) removed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/fabric-tests"))
