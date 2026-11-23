#!/usr/bin/env python3
"""The setup site's Restore from a backup, its questions (setup/site/ask_start, setup/site/ask_restore,
backup/check_whole_restore with changes; manual 1.3.7.10): the first choice as two buttons; the bundle by its number or
a path, its manifest shown; the key and the addresses checked before anything is unpacked, a refusal said and asked
again; the plan's one Proceed, Quit changing nothing; the key only in memory. The questions are answered through the
front end the site uses (common/ask.use_front_end); the bundle's own check is stood in for (a real bundle is
tests/backup/restore_test.py's), the run after Proceed is tests/setup/detach/run_restore_test.py's.

    python3 tests/setup/site/ask_restore_test.py
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fabriclib.backup.check_whole_restore as cwr  # noqa: E402
import fabriclib.setup.site.ask_restore as ar  # noqa: E402
from fabriclib.common.ask import use_front_end  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402
from fabriclib.setup.site.ask_start import ask_start  # noqa: E402
from fabriclib.setup.site.question_view import question_view  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


class Front:
    """Answers by question ID, in order; records what was asked."""

    def __init__(self, answers):
        self.answers, self.asked = {k: list(v) for k, v in answers.items()}, []

    def ask(self, qid, prompt, secret):
        self.asked.append((qid, secret))
        return self.answers[qid].pop(0) if self.answers.get(qid) else ""


class Ctx:
    def __init__(self, base):
        self.deploy_base, self.vars_file, self.restore_key = base, os.path.join(base, "fabric/config/vars.yaml"), None


tmp = tempfile.mkdtemp()
folder = os.path.join(tmp, "backups")
os.makedirs(folder)
NAME = "fabric-fabric-1-20261122T030000Z-uninstall.fabric.tar"
open(os.path.join(folder, NAME), "wb").close()
OTHER = os.path.join(tmp, "copied.fabric.tar")
open(OTHER, "wb").close()
MANIFEST = {"host": "fabric-1", "domain": "lab.test", "host_ip": "10.0.0.5", "lan_cidr": "10.0.0.0/24",
            "lan_gateway": "10.0.0.1", "dns_server": "10.0.0.1", "made": "2026-11-22T03:00:00Z",
            "fabric_version": "0.10.1", "opened_by": "passphrase", "base": tmp,
            "sections": [{"name": "dns"}, {"name": "directory"}, {"name": "secrets", "empty": True}]}
ar.check_bundle = lambda path: dict(MANIFEST)
LISTED = [{"file": NAME, "path": os.path.join(folder, NAME), "kind": "uninstall", "fabric_version": "0.10.1",
           "size": 3 << 20, "error": None},
          {"file": "fabric-x-20261101T000000Z-manual.fabric.tar", "path": "/nowhere", "kind": "manual",
           "fabric_version": None, "size": 0, "error": "not a fabric bundle"}]


def run(answers, refuse=None, bundles=LISTED):
    """ask_restore with these answers; refuse: the messages check refuses with, in turn."""
    front, calls, refusals = Front(answers), [], list(refuse or [])

    def fake_check(base, path, key, version, changes):
        calls.append((path, key, changes))
        if refusals:
            raise ValidationError(refusals.pop(0))

    use_front_end(front)
    ctx = Ctx(tmp)
    try:
        out = ar.ask_restore(ctx, "0.10.1", folder=folder, bundles=lambda f: bundles, check=fake_check)
        return out, None, ctx, front, calls
    except SetupError as exc:
        return None, str(exc), ctx, front, calls
    finally:
        use_front_end(None)


print("--- the first choice")
view = question_view("setup.start", "[N]ew install, or [R]estore from a backup? [n]: ", False)
check("the site shows it as two buttons, New install first (the default every probe accepts)",
      view["choices"] == [["n", "New install"], ["r", "Restore from a backup"]] and not view["secret"], view)
check("the restore's plan is buttons as setup's is", question_view("restore.plan", "[P]roceed or [Q]uit? ",
                                                                  False)["choices"][0][0] == "p")
# covers: ask:setup.start +-
for answer, want in (("n", "new"), ("", "new"), ("r", "restore"), ("Restore", "restore")):
    use_front_end(Front({"setup.start": [answer]}))
    got = ask_start()
    use_front_end(None)
    check(f"{answer!r} -> {want}", got == want, got)
front = Front({"setup.start": ["maybe", "r"]})
use_front_end(front)
got = ask_start()
use_front_end(None)
check("negative: an answer that is neither: asked again", got == "restore" and len(front.asked) == 2, front.asked)

print("--- the questions")
GOOD = {"restore.bundle": ["1"], "restore.key": ["a passphrase for this test"], "restore.plan": ["p"]}
# covers: ask:restore.bundle ask:restore.key ask:restore.plan +
# covers: ask:restore.* +
out, err, ctx, front, calls = run(GOOD)
check("every default kept: the listed bundle, no changes, the key only in memory, nothing moving",
      out == {"bundle": os.path.join(folder, NAME), "changes": {}, "allow_again": False}
      and ctx.restore_key == {"passphrase": "a passphrase for this test", "private_key": None}
      and "a passphrase" not in str(out), (out, err))
check("the key is asked as a secret, the rest not", dict(front.asked)["restore.key"] is True
      and not any(s for q, s in front.asked if q != "restore.key"), front.asked)
check("the addresses are asked with the bundle's as defaults", [q for q, _ in front.asked][2:6] ==
      ["restore.host_ip", "restore.lan_cidr", "restore.lan_gateway", "restore.dns_server"], front.asked)

out, err, ctx, _, calls = run(dict(GOOD, **{"restore.host_ip": ["10.20.0.5"], "restore.lan_cidr": ["10.20.0.0/24"],
                                         "restore.lan_gateway": ["10.20.0.1"]}))
check("another VLAN and subnet: only what changed is a change, and Proceed allows the host changes again",
      out and out["changes"] == {"host_ip": "10.20.0.5", "lan_cidr": "10.20.0.0/24", "lan_gateway": "10.20.0.1"}
      and out["allow_again"] is True and calls[0][2] == out["changes"], (out, calls))
out, err, ctx, _, _ = run(dict(GOOD, **{"restore.bundle": [OTHER],
                                        "restore.key": ["AGE-SECRET-KEY-1QQQ"]}))
check("a path typed, and a scheduled bundle's private key line", out and out["bundle"] == OTHER
      and ctx.restore_key == {"passphrase": None, "private_key": "AGE-SECRET-KEY-1QQQ"}, (out, err))
out, err, _, front, _ = run(dict(GOOD, **{"restore.bundle": ["", OTHER]}), bundles=[])
check("no bundle in the folder: a path is asked, with no default to accept", out and out["bundle"] == OTHER
      and [q for q, _ in front.asked].count("restore.bundle") == 2, (out, front.asked))

# covers: ask:restore.bundle ask:restore.key ask:restore.plan -
# covers: ask:restore.* -
out, err, _, front, _ = run(dict(GOOD, **{"restore.bundle": ["2", "9", "/no/such.tar", "1"]}))
check("negative: a bundle that cannot be read, a number not listed, a path not there: each asked again",
      out and [q for q, _ in front.asked].count("restore.bundle") == 4, front.asked)
def damaged(path):
    if path == OTHER:
        raise ValidationError("its dns section differs from the manifest's")
    return dict(MANIFEST)


ar.check_bundle = damaged
out, err, _, front, _ = run(dict(GOOD, **{"restore.bundle": [OTHER, "1"]}))
ar.check_bundle = lambda path: dict(MANIFEST)
check("negative: a bundle that is not whole: refused, asked again, the good one taken",
      out and out["bundle"] == os.path.join(folder, NAME)
      and [q for q, _ in front.asked].count("restore.bundle") == 2, (err, front.asked))
out, err, ctx, front, calls = run(dict(GOOD, **{"restore.key": ["wrong", "a passphrase for this test"],
                                                "restore.host_ip": ["10.0.0.99", ""]}),
                                  refuse=["the bundle's key does not open it"])
check("negative: a wrong key or a refused address: said, the key and addresses asked again, then accepted",
      out and len(calls) == 2 and [q for q, _ in front.asked].count("restore.key") == 2
      and ctx.restore_key["passphrase"] == "a passphrase for this test", (out, calls))
out, err, ctx, _, _ = run(dict(GOOD, **{"restore.plan": ["q"]}))
check("negative: Quit at the plan: stops, nothing restored, no key kept", out is None and "nothing was restored"
      in (err or "") and ctx.restore_key is None, err)
os.makedirs(os.path.dirname(Ctx(tmp).vars_file))
open(Ctx(tmp).vars_file, "w").close()
out, err, _, front, _ = run(GOOD)
check("negative: fabric already installed here: refused before any question, pointing to the console",
      "fabric is installed here" in (err or "") and not front.asked, err)
os.remove(Ctx(tmp).vars_file)

print("--- the check before anything is unpacked (check_whole_restore with changes)")
cwr.check_bundle = lambda path: dict(MANIFEST)
seen = {}


def whole(changes, problem=""):
    seen.clear()
    try:
        cwr.check_whole_restore(tmp, OTHER, {"passphrase": "x"}, "0.10.1", changes,
                                problem=lambda a: seen.update(a) or problem, opens=lambda p, **k: None)
        return None
    except ValidationError as exc:
        return str(exc)


check("a new network: the new addresses are the ones checked on this host",
      whole({"host_ip": "10.20.0.5", "lan_cidr": "10.20.0.0/24", "lan_gateway": "10.20.0.1"}) is None
      and seen == {"host_ip": "10.20.0.5", "lan_cidr": "10.20.0.0/24", "lan_gateway": "10.20.0.1"}, seen)
err = whole({"host_ip": "10.20.0.5", "lan_cidr": "10.20.0.0/24", "lan_gateway": "10.20.0.1"},
            "10.20.0.5 is not an address of this machine")
check("negative: a new address this host does not have yet: refused, give it first (4.2.4.8)",
      "Give this host its new address first" in (err or "") and "4.2.4.8" in err, err)
check("negative: a gateway outside the new subnet: check_changes refuses",
      "must both be in" in (whole({"host_ip": "10.20.0.5", "lan_cidr": "10.20.0.0/24"}) or ""))
check("negative: the host's name: refused, rename after the restore", "4.2.4.3" in (whole({"hostname": "x"}) or ""))
check("no changes: the bundle's own addresses, as before", whole({}) is None and seen["host_ip"] == "10.0.0.5", seen)

print("--- the finish shows what moved")
from fabriclib.setup.site.listener.page_for import _restored  # noqa: E402
html = _restored({"changed": {"host_ip": ["10.0.0.5", "10.20.0.5"]}, "leftover": [["dns.x.A.<far>", "10.0.0.9"]]})
check("each change old -> new, and the admin's settings still naming the old address, escaped",
      "10.0.0.5 → 10.20.0.5" in html and "still name the old address" in html and "&lt;far&gt;" in html
      and "<far>" not in html, html)
check("a restore that moved nothing says so", "back at the bundle's addresses" in _restored({"changed": {}}))
check("a new install: nothing added to its finish", _restored(None) == "")

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
