#!/usr/bin/env python3
"""The host's own ufw rules split for ufw (security/ufw_own_rule_args, manual 1.2.8): a comment's quotes go, its words
stay; lines that are not ufw commands give nothing. Pure.

    python3 tests/security/ufw_own_rule_args_test.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "src"))
from fabriclib.security.ufw_own_rule_args import ufw_own_rule_args  # noqa: E402

FAILED = 0


def check(name, got, want):
    global FAILED
    FAILED += got != want
    print(("PASS " if got == want else "FAIL ") + name + ("" if got == want else f"  -> {got!r}"))


check("positive: a comment in quotes (the 0.10.0 rehearsal's rule, 2.3.1.57) loses its quotes",
      ufw_own_rule_args("ufw allow 8443/tcp comment 'own-app'"), ["allow", "8443/tcp", "comment", "own-app"])
check("positive: a comment of several words stays one argument",
      ufw_own_rule_args("ufw allow 9000/tcp comment 'my app here'"), ["allow", "9000/tcp", "comment", "my app here"])
check("positive: a rule with no comment, from a network",
      ufw_own_rule_args("ufw allow from 10.88.0.0/24 to any port 22 proto tcp"),
      ["allow", "from", "10.88.0.0/24", "to", "any", "port", "22", "proto", "tcp"])
check("negative: not a ufw command: nothing", ufw_own_rule_args("iptables -A INPUT -j ACCEPT"), [])
check("negative: an unclosed quote: nothing (never a half rule)", ufw_own_rule_args("ufw allow 1/tcp comment 'x"), [])
check("negative: `ufw` alone: nothing", ufw_own_rule_args("ufw"), [])
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
