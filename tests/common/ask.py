"""fabriclib/common/ask.py (manual 1.1.5.6), the one place fabric asks a person: what it returns for an answer, an empty
answer with and without a default, a secret; that EOF and Ctrl-C reach the caller as they did from input() and
getpass(); a malformed question ID refused before anything is asked. No containers, nothing on the host changed:
input() and getpass() are stood in for, as the consent suite answers setup's questions (the global Rule 9 allows a
stand-in in a unit test of pure logic; no container is involved).
    python3 tests/common/ask.py
"""
import builtins
import getpass
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.ask import ask, ask_secret  # noqa: E402

FAILED = 0
SEEN = []


def check(name, cond, detail=""):
    """Purpose: print one PASS/FAIL line and count the failures.
    Inputs:  name — what is proven; cond — bool; detail — shown on failure.
    Returns: None.
    Fails:   never.
    Feeds:   this suite."""
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def answering(value):
    """Purpose: a stand-in for input()/getpass() that records the prompt and returns value, or raises it when it is
             an exception.
    Inputs:  value — str, or an exception instance.
    Returns: the stand-in function.
    Fails:   never (the stand-in raises value when it is an exception).
    Feeds:   this suite."""
    def stand_in(prompt=""):
        SEEN.append(prompt)
        if isinstance(value, BaseException):
            raise value
        return value
    return stand_in


def raised(fn):
    """Purpose: the exception type fn raises, or None.
    Inputs:  fn — a function of no arguments.
    Returns: an exception class or None.
    Fails:   never.
    Feeds:   this suite."""
    try:
        fn()
    except BaseException as e:      # KeyboardInterrupt included: that is what is checked
        return type(e)
    return None


real_input, real_getpass = builtins.input, getpass.getpass
try:
    print("--- answers")
    builtins.input = answering("  yes \n")
    check("the answer comes back stripped, the prompt shown exactly as given",
          ask("test.answer", "  Allow? [y/n] ") == "yes" and SEEN[-1] == "  Allow? [y/n] ", SEEN)
    check("an answer wins over the default", ask("test.answer", "Priority [10]: ", "10") == "yes")
    builtins.input = answering("   ")
    check("an empty answer takes the default", ask("test.default", "Priority [10]: ", "10") == "10")
    check("an empty answer without a default is the empty string", ask("test.default", "Name: ") == "")
    check("an empty default is returned as such (\"\" or the answer)", ask("test.default", "Out: ", "") == "")
    builtins.input = answering("x")
    check("an ID built from a key is accepted", ask("menu.vars.Some-Key 1", "Value: ") == "x")
    getpass.getpass = answering(" s3cret \n")
    check("a secret comes back exactly as typed (the caller trims), through getpass with the prompt as given",
          ask_secret("test.secret", "token: ") == " s3cret \n" and SEEN[-1] == "token: ", SEEN)

    print("--- refusals")
    builtins.input = answering(EOFError())
    check("EOF at a question propagates as EOFError, as from input()",
          raised(lambda: ask("test.eof", "Allow? ")) is EOFError)
    check("... also when a default is given (closed stdin is not an empty answer)",
          raised(lambda: ask("test.eof", "Allow? ", "y")) is EOFError)
    builtins.input = answering(KeyboardInterrupt())
    check("Ctrl-C at a question propagates as KeyboardInterrupt", raised(lambda: ask("test.ctrl_c", "? ")) is
          KeyboardInterrupt)
    getpass.getpass = answering(EOFError())
    check("EOF at a secret propagates as EOFError, as from getpass", raised(lambda: ask_secret("test.eof", "pin: "))
          is EOFError)
    SEEN.clear()
    for bad in ("", "noarea", ".name", "Setup.x", None, 3):
        check(f"a malformed question ID ({bad!r}) is refused with ValueError, nothing asked",
              raised(lambda: ask(bad, "? ")) is ValueError and raised(lambda: ask_secret(bad, "? ")) is ValueError
              and not SEEN, SEEN)
finally:
    builtins.input, getpass.getpass = real_input, real_getpass

print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
