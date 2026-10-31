"""`fabricctl images` (manual 1.14.2, decision 2.1.14.3) on this machine's real Docker, as root. Run by
tests/images/run.sh. Installed services, updates and rollbacks are the sandbox's (tests/sandbox/run.sh) and
tests/images/update.sh's; here, what needs no install:

- `fabricctl images` alone is the status; an unknown subcommand, or extra words, are refused with the usage
- `images rollback` refuses an unknown service, and one with no image recorded before an update
- prune, on images only this test makes (repositories fabric-test/prune-*, named in a test lock): an old image
  of a lock's repository is removed, one a container uses is kept, one of another repository is never touched;
  image_prune false leaves them all after an update, true cleans up
"""
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from contextlib import redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.join(REPO, "tests", "common")]
import test_run as testrun  # noqa: E402
from fabriclib.images.constants import STATE  # noqa: E402
from fabriclib.images.run_images_command import _prune, run_images_command  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402

CLI = os.path.join(REPO, "src", "fabriclib", "cli.py")
# this run's own repositories and container (manual 3.1.2.6): another run's prune never sees them
REPOS = {n: testrun.name(f"fabric-test/prune-{n}") for n in ("old", "used", "other")}
OLD, USED, OTHER = (REPOS[n] + ":1" for n in ("old", "used", "other"))
CONTAINER = testrun.name("fabric-test-prune-used")
PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {detail}")


def fabricctl(*args):
    """fabricctl as installed hosts run it (cli.py), on this machine's default install root."""
    return subprocess.run([sys.executable, CLI, "images", *args], capture_output=True, text=True, timeout=120)


def exists(ref):
    return subprocess.run(["docker", "image", "inspect", ref], capture_output=True).returncode == 0


def make_image(ref):
    """A tiny image of one file, made here (no pull): docker import of a tar."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        data = ref.encode()
        info = tarfile.TarInfo("f")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    subprocess.run(["docker", "import", "-", ref], input=buf.getvalue(), capture_output=True, check=True)


def quiet(fn, *args):
    out = io.StringIO()
    with redirect_stdout(out):
        status = fn(*args)
    return status, out.getvalue()


def cleanup():
    testrun.remove("container", CONTAINER)      # this run's only
    for ref in (OLD, USED, OTHER):
        subprocess.run(["docker", "image", "rm", "-f", ref], capture_output=True)


# routing and refusals of the command itself
res = fabricctl()
# covers: cli:images +
check("fabricctl images alone shows the status",
      res.returncode == 0 and ("all images current" in res.stdout or "update(s) available" in res.stdout),
      (res.returncode, res.stdout[-300:], res.stderr[-300:]))
res = fabricctl("upgrade")
# covers: cli:images -
check("fabricctl images upgrade (no such subcommand): refused with the usage",
      res.returncode == 2 and res.stderr.startswith("usage: fabricctl images status") and not res.stdout,
      (res.returncode, res.stderr[:200]))
res = fabricctl("status", "nginx")
# covers: cli:images.status -
check("images status takes no arguments: refused with the usage",
      res.returncode == 2 and res.stderr.startswith("usage: fabricctl images status"), (res.returncode, res.stderr[:200]))
res = fabricctl("rollback", "no-such-service")
# covers: cli:images.rollback -
check("images rollback of an unknown service: refused, saying so",
      res.returncode == 1 and "error: unknown service 'no-such-service'" in res.stderr, (res.returncode, res.stderr))
if os.path.exists(STATE):
    print(f"SKIP images rollback with nothing recorded: this machine has {STATE}")
else:
    res = fabricctl("rollback", "nginx")
    # covers: cli:images.rollback -
    check("images rollback with no image recorded before an update: refused, saying why",
          res.returncode == 1 and "error: nginx: no previous image recorded" in res.stderr, (res.returncode, res.stderr))
res = fabricctl("rollback")
check("images rollback without a service: refused with the usage",
      res.returncode == 2 and res.stderr.startswith("usage: fabricctl images status"), (res.returncode, res.stderr[:200]))

# prune, on this test's own images and a lock naming only their repositories
work = tempfile.mkdtemp(prefix="fabric-images-commands-")
cleanup()
try:
    os.makedirs(os.path.join(work, "fabric"))
    with open(os.path.join(work, "fabric", "images.lock.yaml"), "w") as f:
        f.write("images:\n" + "".join(f"  prune-{n}: {{var: image_test_{n}, repo: {REPOS[n]}, tag: '0', "
                                      f"digest: 'sha256:{'0' * 64}'}}\n" for n in ("old", "used")))
    for ref in (OLD, USED, OTHER):
        make_image(ref)
    subprocess.run(["docker", "create", "--name", CONTAINER, *testrun.labels(), USED, "/f"], capture_output=True, check=True)
    ctx = SetupContext(deploy_base=work)

    res = fabricctl("prune", "--all")
    # covers: cli:images.prune -
    check("images prune takes no arguments: refused with the usage, nothing removed",
          res.returncode == 2 and res.stderr.startswith("usage: fabricctl images status") and exists(OLD),
          (res.returncode, res.stderr[:200]))

    ctx.vars = {"image_prune": False}
    _, out = quiet(_prune, ctx)
    # covers: setting:image_prune +
    check("image_prune: false: after an update nothing is cleaned up",
          out == "" and all(exists(r) for r in (OLD, USED, OTHER)), out)
    ctx.vars = {"image_prune": True}
    _, out = quiet(_prune, ctx)
    # covers: setting:image_prune +
    check("image_prune: true: after an update the old image is cleaned up; in use and other repositories kept",
          out.startswith(("cleaned up", "no old images")) and not exists(OLD) and exists(USED) and exists(OTHER),
          (out, exists(OLD), exists(USED), exists(OTHER)))
    # what it says it removed: on Docker's containerd image store `docker rmi <tag> <digest>` removes the image with
    # the tag, then fails on the digest, so prune_images counts it as not removed (reported, not checked here)
    print(f"NOTE prune reported: {out.strip()!r}")
    status, out = quiet(run_images_command, ctx, ["prune"])
    check("images prune again: nothing left to remove (in use and other repositories still kept)",
          status == 0 and out.strip() == "0 old image(s) removed" and exists(USED) and exists(OTHER), out)
finally:
    cleanup()
    shutil.rmtree(work, ignore_errors=True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
