import re

from fabriclib.common.ask import ask
from fabriclib.common.errors import ValidationError
from fabriclib.dns.key_record_choices import key_record_choices
from fabriclib.dns.list_zones import list_zones


def _pick(question, count):
    """Purpose: One number from a numbered list, asked again until it is one.
    Inputs:  question — () -> str: asks the question (ask() with its literal ID and default); count — how many.
    Returns: int, 1-based.
    Fails:   EOFError when stdin ends (the caller says so).
    Feeds:   ask_tsig_scope."""
    while True:
        got = question()
        if got and got.isdigit() and 1 <= int(got) <= count:
            return int(got)
        print(f"  answer a number from 1 to {count}")


def ask_tsig_scope(data):
    """Purpose: `fabricctl tsig add <name>` with no scope given asks what the console's New key asks (decision
             2.1.4.12): the mode first; ACME (DNS-01): the zone, then the zone's records by number (a record's
             number with "+" picks it with its aliases, 2.1.4.14); Custom: the zone and today's scopes.
    Inputs:  data — the vars (domain, dns).
    Returns: the key's scope fields for add_tsig_key: {"domain", "records"?, "records_with_aliases"?} for ACME;
             {"domain", "records"} | {"domain", "primary": True} | {"domain", "any_name": True, "record_types"} for
             Custom.
    Fails:   ValidationError "no answer: …" when stdin ends before a question is answered, "the zone has no records
             to pick: …" for an empty zone, "no names given" for Custom's listed names left empty.
    Feeds:   run_tsig_command (add)."""
    try:
        mode = _pick(lambda: ask("tsig.mode", "Mode: 1) ACME (DNS-01): pick the zone's records  2) Custom [1]: ",
                                 "1"), 2)
        zones = [z["name"] for z in list_zones() if not z["reverse"]]
        print("\n".join(f"  {i}) {z}" for i, z in enumerate(zones, 1)))
        site = zones.index(data.get("domain")) + 1 if data.get("domain") in zones else 1
        zone = zones[_pick(lambda: ask("tsig.zone", f"Zone [{site}]: ", str(site)), len(zones)) - 1]
        if mode == 1:
            choices = key_record_choices(data, zone)
            if not choices:
                raise ValidationError(f"the zone has no records to pick: {zone} (add one, or make a Custom key)")
            for i, c in enumerate(choices, 1):
                more = f"   {i}+ with its aliases: {', '.join(c['aliases'])}" if c["aliases"] else ""
                print(f"  {i}) {c['name']} ({' '.join(c['types'])}){more}")
            while True:
                got = ask("tsig.records", "Records it may prove, by number (e.g. 1,3+): ")
                picks = [p for p in re.split(r"[\s,]+", got or "") if p]
                ok = picks and all(re.fullmatch(r"\d+\+?", p) and 1 <= int(p.rstrip("+")) <= len(choices)
                                   and (not p.endswith("+") or choices[int(p[:-1]) - 1]["address"]) for p in picks)
                if ok:
                    break
                print(f"  numbers from 1 to {len(choices)}; '+' only after an A or AAAA record")
            out = {"domain": zone}
            records = [choices[int(p) - 1]["name"] for p in picks if not p.endswith("+")]
            aliases = [choices[int(p[:-1]) - 1]["name"] for p in picks if p.endswith("+")]
            if records:
                out["records"] = list(dict.fromkeys(records))
            if aliases:
                out["records_with_aliases"] = list(dict.fromkeys(aliases))
            return out
        scope = _pick(lambda: ask("tsig.custom_scope", "May update: 1) listed hosts' DNS-01 names  2) any "
                                  "_acme-challenge name in the zone  3) any name, chosen record types [1]: ", "1"), 3)
        if scope == 1:
            hosts = [h for h in re.split(r"[\s,]+", ask("tsig.hosts", "Hosts, comma-separated: ") or "") if h]
            if not hosts:
                raise ValidationError("no names given")
            return {"domain": zone, "records": hosts}
        if scope == 2:
            return {"domain": zone, "primary": True}
        types = [t.upper() for t in re.split(r"[\s,]+", ask("tsig.types", "Record types [TXT]: ", "TXT")) if t]
        return {"domain": zone, "any_name": True, "record_types": types}
    except EOFError:
        raise ValidationError("no answer: give the scope with flags (--mode, --record, --any-name; "
                              "fabricctl tsig --help)") from None
