#!/usr/bin/env python3
"""The setup menu's zone editor asks the subnets a new record answers (menu/edit_dns_zone, decision 2.1.4.17, manual
1.4.1.12, 4.4.1.6): Enter keeps the host's LAN, `all` or subnets are taken as typed, a reverse zone is not asked; what
was typed is checked as the console's is, so a subnet not offered is refused, saying why. The terminal and the
settings stood in for. Pure; no container.

    python3 tests/menu/edit_dns_zone_test.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.menu.edit_dns_zone as edz  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dns.split.record_subnets import record_subnets  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


V = {"lan_cidr": "10.1.10.0/24"}
PLAN = {"subnets": [{"name": "iot", "cidr": "10.1.20.0/24"}]}
asked = []


def answers(**given):
    """ask() as a person answering: given[qid], else Enter (the default)."""
    def ask(qid, prompt, default=None):
        asked.append((qid, prompt))
        got = given.get(qid, "")
        return default if not got and default is not None else got
    return ask


edz.load_vars = lambda: V
edz.offered_subnets = lambda v: [{"cidr": "10.1.10.0/24", "label": "10.1.10.0/24 (host's LAN)"},
                                 {"cidr": "10.1.20.0/24", "label": "10.1.20.0/24 (iot)"}]


def prompt(zone="dynamic_zone_var", **given):
    asked.clear()
    edz.ask = answers(**{"menu.dns.record.name": "web", "menu.dns.record.ip": "10.1.20.5", **given})
    return edz._prompt_record("A", zone)


def checked(form):
    try:
        return record_subnets("dynamic_zone_var", "A", {"name": "web", "ip": "10.1.20.5"}, form, {}, V, plan=PLAN)
    except ValidationError as exc:
        return str(exc)


form = prompt()
# covers: ask:menu.dns.record.subnets +
check("positive: Enter keeps the host's LAN, shown as the default", form.get("subnets") == "10.1.10.0/24"
      and ("menu.dns.record.subnets", "Subnets [10.1.10.0/24]: ") in asked, (form, asked))
check("...and the record answers the host's LAN alone", checked(form) == {"name": "web", "ip": "10.1.20.5",
                                                                          "subnets": ["10.1.10.0/24"]}, checked(form))
form = prompt(**{"menu.dns.record.subnets": "10.1.10.0/24,10.1.20.0/24"})
check("positive: several subnets, as typed", checked(form).get("subnets") == ["10.1.10.0/24", "10.1.20.0/24"],
      checked(form))
check("positive: all: every subnet", checked(prompt(**{"menu.dns.record.subnets": "all"})) == {"name": "web",
                                                                                              "ip": "10.1.20.5"})
form = prompt(zone="10.1.20.in-addr.arpa")
check("a reverse zone: the subnets are not asked (it answers every subnet)", "subnets" not in form
      and not any(q == "menu.dns.record.subnets" for q, _ in asked), asked)
# covers: ask:menu.dns.record.subnets -
why = checked(prompt(**{"menu.dns.record.subnets": "10.9.0.0/24"}))
check("negative: a subnet not offered: refused, saying why", isinstance(why, str)
      and "neither the host's LAN nor a subnet of the site's plan" in why, why)
why = checked(prompt(**{"menu.dns.record.subnets": "all 10.1.20.0/24"}))
check("negative: all beside a subnet: refused", isinstance(why, str) and "pick it alone" in why, why)
V["dns_filter"] = "none"
why = checked(prompt())
check("negative: the DNS filter off: the new record refused, saying to turn the filter on (2.1.4.17.3)",
      isinstance(why, str) and "a new record needs the DNS filter on" in why, why)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
