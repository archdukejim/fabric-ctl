#!/usr/bin/env python3
"""`fabricctl dhcp rotate-key` (decision 2.1.10.42, manual 1.10.4.43): Kea's DNS key replaced now whatever its age,
the new key saved and audited before the apply that finishes it; refused, changing nothing, with DHCP off, Kea
registering no names, or no key made yet; a replacement under way finished by the apply. The secrets' store and the
apply stood in for (the real BIND and Kea: tests/kea/reload.py); the CLI as fabricctl routes it.

    python3 tests/dhcp/kea_key/rotate_key_test.py
"""
import contextlib
import io
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.dhcp.kea_key.rotate_key as m_rotate  # noqa: E402
import fabriclib.dhcp.run_dhcp_command as m_cli  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0
V = {"install_kea": True, "dhcp": {"ddns": True}}
m_rotate.vars_lock = contextlib.nullcontext


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def run(v, secrets, ok=True):
    """rotate_key with its store and apply stood in for: (result or the refusal, saved, audited, applied)."""
    saved, audited, applied = [], [], []
    try:
        out = m_rotate.rotate_key(v, "root", load=lambda path: dict(secrets),
                                  save=lambda update, path: saved.append(update),
                                  audit=lambda *a: audited.append(a),
                                  apply=lambda actor, source="cli": (applied.append(actor), (ok, "x" * 3000))[1])
    except ValidationError as e:
        out = str(e)
    return out, saved, audited, applied


out, saved, audited, applied = run(V, {"kea_ddns_secret": "c2VjcmV0", "kea_ddns_made": "2026-10-01"})
check("a key 23 days old replaced when asked: the new key saved with the old one kept, audited, then applied",
      isinstance(out, dict) and "asked for" in out["started"] and out["ok"] is True and len(out["output"]) == 2000
      and saved and saved[0]["kea_ddns_old"]["name"] == "kea-ddns" and saved[0]["kea_ddns_key"].startswith(
          "kea-ddns-") and audited[0][1] == "KEA_KEY_ROTATE" and "(asked for)" in audited[0][2]
      and applied == ["root"], (out, saved, audited))
out, saved, audited, applied = run(V, {"kea_ddns_secret": "bmV3", "kea_ddns_key": "kea-ddns-20261024",
                                       "kea_ddns_old": {"name": "kea-ddns", "secret": "b2xk", "made": None}})
check("a replacement under way: nothing new started or saved; the apply finishes it", isinstance(out, dict)
      and out["started"] is None and saved == [] and applied == ["root"], (out, saved))
for name, v, secrets, why in (
        ("DHCP off", {"install_kea": False}, {"kea_ddns_secret": "x"}, "DHCP is off here"),
        ("Kea registering no names", {"install_kea": True, "dhcp": {"ddns": False}}, {"kea_ddns_secret": "x"},
         "registers no names"),
        ("no key made yet", V, {}, "not made yet")):
    out, saved, audited, applied = run(v, secrets)
    check(f"refused: {name}, saying why; nothing saved, audited or applied", isinstance(out, str) and why in out
          and saved == audited == applied == [], (out, saved, applied))

# the CLI, as fabricctl routes it (run_dhcp_command)
m_cli.rotate_key = lambda v, actor: {"started": "Kea's DNS key kea-ddns (asked for) is replaced by kea-ddns-20261024",
                                     "ok": True, "output": ""}
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc = m_cli.run_dhcp_command(V, ["rotate-key"])
# covers: cli:dhcp.rotate-key +
check("fabricctl dhcp rotate-key: says what is replaced, then that Kea runs on the new key; exit 0", rc == 0
      and "replaced by kea-ddns-20261024" in buf.getvalue() and "Kea runs on the new key" in buf.getvalue(),
      buf.getvalue())
m_cli.rotate_key = lambda v, actor: {"started": None, "ok": False, "output": "Error: BIND9 did not accept"}
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc = m_cli.run_dhcp_command(V, ["rotate-key"])
check("the apply failing: its output shown, exit 1 (a replacement under way said)", rc == 1
      and "BIND9 did not accept" in buf.getvalue() and "under way" in buf.getvalue(), buf.getvalue())
m_cli.rotate_key = m_rotate.rotate_key
err = io.StringIO()
with contextlib.redirect_stderr(err):
    rc = m_cli.run_dhcp_command({"install_kea": False}, ["rotate-key"])
    rc2 = m_cli.run_dhcp_command(V, ["rotate-key", "now"])
# covers: cli:dhcp.rotate-key -
check("refused: DHCP off (exit 1, why); an argument it does not take (exit 2, the usage)", rc == 1 and rc2 == 2
      and "DHCP is off here" in err.getvalue() and "rotate-key" in err.getvalue(), err.getvalue())

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
