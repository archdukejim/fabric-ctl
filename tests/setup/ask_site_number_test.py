"""Setup's question for the site's number (manual 1.10.4.18.1, decision 2.1.10.16): asked once, after the domain
controller runs; the suggestion its default, taken unattended; a bad number refused, saying why, and asked again; a
read-only DC's site, a site already numbered and a domain that does not answer not asked. Pure logic: the plan's read
and write and the terminal are stood in for (the federation and lab suites meet the real DC).
    python3 tests/setup/ask_site_number_test.py"""
import io
import os
import sys
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.setup.ask_site_number as asn  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


V = {"site_name": "home", "ad_dc_type": "dc"}
SITES = [{"name": "hq", "created": "1", "block": 1}, {"name": "home", "created": "2", "block": None},
         {"name": "lab", "created": "3", "block": 3}]
WRITES, ASKED = [], []
STATE = {"read": None, "write": None, "answers": []}


def fake_read(v, secrets, of="", container="samba"):
    if isinstance(STATE["read"], Exception):
        raise STATE["read"]
    return STATE["read"]


def fake_set(v, actor, number, secrets=None, container="samba", source="cli"):
    if STATE["write"]:
        raise STATE["write"]
    WRITES.append((actor, number, source))


def fake_ask(qid, prompt, default=None):
    ASKED.append(qid)
    answer = STATE["answers"].pop(0)
    return default if answer == "" and default is not None else answer


asn.read_plan, asn.set_block, asn.ask = fake_read, fake_set, fake_ask


def run(v=None, sites=None, non_interactive=False, tty=True, answers=(), read=None, write=None):
    STATE.update(read=read if read is not None else {"sites": [dict(s) for s in (sites or SITES)], "plans": {}},
                 write=write, answers=list(answers))
    del WRITES[:], ASKED[:]
    out = io.StringIO()
    with redirect_stdout(out):
        lines = asn.ask_site_number(v or V, {"ad_agent_password": "x"}, non_interactive, container="c", tty=tty)
    return lines, out.getvalue()


# covers: ask:setup.site_number +
lines, shown = run(answers=[""])
check("Enter takes the suggestion (its order in the organisation: 2), written by setup",
      ASKED == ["setup.site_number"] and WRITES == [("setup", 2, "setup")] and "site number: 2" in lines[0],
      (lines, WRITES, ASKED))
lines, _ = run(answers=["7"])
check("a number typed is written", WRITES == [("setup", 7, "setup")] and lines == [
    "site number: 7 (fabricctl ipam block to change it)"], (lines, WRITES))
lines, _ = run(non_interactive=True)
check("unattended (--non-interactive): the suggestion taken, nothing asked", ASKED == [] and WRITES == [
    ("setup", 2, "setup")], (ASKED, WRITES))
lines, _ = run(tty=False)
check("no terminal (setup's detached worker): the suggestion taken, nothing asked", ASKED == [] and WRITES == [
    ("setup", 2, "setup")], (ASKED, WRITES))
lines, _ = run(sites=[{"name": "hq", "created": "1", "block": 2}, {"name": "home", "created": "2", "block": None}],
               non_interactive=True)
check("the suggestion skips a number another site has", WRITES == [("setup", 3, "setup")], WRITES)

# covers: ask:setup.site_number -
lines, shown = run(answers=["0", "abc", "3", "9"])
check("refused, saying why, and asked again: 0, not a number, another site's; then 9 taken",
      ASKED == ["setup.site_number"] * 4 and WRITES == [("setup", 9, "setup")] and "1 to 255" in shown
      and "already lab's" in shown, (ASKED, WRITES, shown))
lines, _ = run(sites=[{"name": "hq", "created": "1", "block": 1}, {"name": "home", "created": "2", "block": 4}])
check("a site already numbered: not asked, nothing written, nothing said", lines == [] and ASKED == [] and WRITES == [],
      (lines, ASKED))
lines, _ = run(v={"site_name": "home", "ad_dc_type": "rodc"})
check("a read-only DC's site: not asked, nothing written; the command and the writable partner named",
      ASKED == [] and WRITES == [] and "read-only" in lines[0] and "fabricctl ipam block 2" in lines[0]
      and "writable partner" in lines[0], lines)
lines, _ = run(read=ValidationError("the DC did not answer"))
check("the domain not answering: not asked, left for later, saying so", ASKED == [] and WRITES == []
      and "did not answer" in lines[0] and "fabricctl ipam block" in lines[0], lines)
lines, _ = run(answers=["5"], write=ValidationError("insufficient access"))
check("the write refused: said, with the command to set it later", "5 could not be written" in lines[0]
      and "insufficient access" in lines[0] and "fabricctl ipam block 5" in lines[0], lines)
lines, _ = run(sites=[{"name": f"s{n}", "created": str(n), "block": n} for n in range(1, 256)]
               + [{"name": "home", "created": "999", "block": None}], non_interactive=True)
check("every number taken: none given, nothing written", WRITES == [] and "every number" in lines[0], lines)
lines, _ = run(v={"ad_dc_type": "dc"})
check("no site name: nothing to number, nothing read", lines == [] and WRITES == [], lines)

print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
