"""setup with no terminal (decision 2.1.3.4): refused before anything is asked, saying how to run it unattended, where
it used to end in a Python EOFError at its Guided/Advanced question. Pure: setup's steps are never reached.
    python3 tests/setup/require_terminal_test.py"""
import io
import os
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.setup.run_setup as rsu  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402
from fabriclib.setup.require_terminal import require_terminal  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def refused(fn):
    try:
        fn()
        return ""
    except SetupError as e:
        return str(e)


check("positive: at a terminal, nothing is refused", refused(lambda: require_terminal(False, lambda: True)) == "")
check("positive: --non-interactive with no terminal: nothing is asked, nothing refused",
      refused(lambda: require_terminal(True, lambda: False)) == "")
why = refused(lambda: require_terminal(False, lambda: False))
check("negative: no terminal and questions to come: refused, naming --non-interactive and --file",
      "no terminal" not in why and "there is none here" in why and "--non-interactive" in why and "--file FILE" in why
      and "Nothing was asked or changed" in why, why)


class Asked(Exception):
    """a question was reached"""


def asked(ctx):
    raise Asked()


rsu.choose_mode = asked
rsu.unit_running = lambda: False
ran = []
rsu.run_steps = lambda ctx, steps, selected, guided=False: ran.append(selected) or 0
rsu.ask_consent = lambda *a, **k: {}
rsu.plan_host_changes = lambda *a, **k: {}
rsu.ufw_active = lambda: False


def main(*args):
    """run_setup's main with stdin no terminal (an empty pipe: the EOFError's case); (exit code, output, asked)."""
    saved = sys.stdin, sys.stdout, sys.stderr
    sys.stdin, sys.stdout = io.StringIO(""), io.StringIO()
    sys.stderr = sys.stdout
    try:
        try:
            code, reached = rsu.main(list(args)), False
        except Asked:
            code, reached = None, True
        return code, sys.stdout.getvalue(), reached
    finally:
        sys.stdin, sys.stdout, sys.stderr = saved


with tempfile.TemporaryDirectory() as d:
    code, out, reached = main("--deploy-base", d)
    # covers: cli:setup -
    check("negative: `fabricctl setup` with stdin no terminal: exit 1 with the refusal, before the Guided/Advanced "
          "question, nothing written", code == 1 and not reached and "--non-interactive" in out
          and not os.path.exists(os.path.join(d, "fabric")), (code, reached, out))
    code, out, reached = main("--deploy-base", d, "--file", os.path.join(d, "x.yaml"))
    check("negative: --file alone still asks (the mode, what the file leaves out): refused the same way",
          code == 1 and not reached and "--non-interactive" in out, (code, reached, out))
    code, out, reached = main("--deploy-base", d, "--step", "certs")
    check("positive: a step that needs no input runs with no terminal", code == 0 and ran == [["certs"]], (code, out))
print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
