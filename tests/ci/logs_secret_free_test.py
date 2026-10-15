"""CI's check before the logs are kept (3.1.2.4): a log holding one of the run's secrets is removed and the step fails.
    python3 tests/ci/logs_secret_free_test.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts", "ci"))
import logs_secret_free as lsf  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


with tempfile.TemporaryDirectory() as root:
    write(root, "sandbox/admin-pw", "Fx9-0123456789abcdef\n")
    write(root, "sandbox/vars.yaml", "tsig_keys:\n- {name: npm, secret: c2VjcmV0LXRzaWcta2V5LXZhbHVl}\n")
    write(root, "sandbox/run.py", "password = 'not-a-secret-file'\n")
    clean = write(root, "sandbox/setup.log", "fabric is ready\n")
    top = write(root, "sandbox.log", "222 passed, 0 failed\n")
    found = lsf.secrets_in(root)
    check("the run's secrets: a password file's content and a YAML secret's value; not a script's text",
          "Fx9-0123456789abcdef" in found and "c2VjcmV0LXRzaWcta2V5LXZhbHVl" in found
          and not any("not-a-secret" in s for s in found), found)
    check("clean logs pass, all kept", lsf.main(root) == 0 and os.path.exists(clean) and os.path.exists(top))
    leaked = write(root, "sandbox/uninstall.log", "export ok\nkey c2VjcmV0LXRzaWcta2V5LXZhbHVl\n")
    pw = write(root, "sandbox/deep/nested/admin.log", "typed Fx9-0123456789abcdef\n")
    check("negative: a log holding a secret, at any depth, is removed and the step fails; the others kept",
          lsf.main(root) == 1 and not os.path.exists(leaked) and not os.path.exists(pw) and os.path.exists(clean))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
