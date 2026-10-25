import datetime

from fabriclib.common.ask import ask, ask_yes_no
from fabriclib.common.errors import ValidationError
from fabriclib.ipam.add_address import add_address


def offer_reservations(v, result, secrets=None, container="samba", ask=ask, ask_yes_no=ask_yes_no):
    """Purpose: after a scan on a terminal, ask for each address in use but unrecorded whether to record it
             (decision 2.1.10.13: it informs and asks, never blocks): "make it a reservation?" when ARP saw its MAC
             (the existing reservation unit, add_address), else "record it?" and then its MAC, typed, to make it
             a reservation, or Enter for a static address (2.1.10.50, manual 1.10.4.47). The answer no (the
             default) leaves it; a refusal (a rule of the plan, a bad MAC) is printed and the next is asked.
    Inputs:  v — fabric vars; result — scan_subnet's result; secrets, container — as add_address; ask,
             ask_yes_no — the prompts (fabriclib/common/ask; question IDs ipam.scan_record, ipam.scan_mac and
             ipam.scan_name).
    Returns: list of the addresses recorded (add_address's results).
    Fails:   EOFError / KeyboardInterrupt from the prompts propagate; OSError from add_address's audit or copy.
    Feeds:   run_ipam_command (scan)."""
    done = []
    stamp = datetime.date.today().isoformat()
    for f in result["answering"]:
        if f["status"] != "unrecorded":
            continue
        question = (f"make {f['ip']} ({f['mac']}) a reservation" if f["mac"]
                    else f"record {f['ip']} (no MAC: ARP did not see it)")
        if not ask_yes_no("ipam.scan_record", question, False):
            continue
        mac = f["mac"] or ask("ipam.scan_mac", "    its MAC, to make it a reservation (Enter: a static address): ",
                              "").strip()
        kind = "reservation" if mac else "static"
        name = ask("ipam.scan_name", f"    name for {f['ip']} (one DNS label, Enter for none): ", "")
        try:
            out = add_address(v, "root", f["ip"], kind, "", name, mac, "", f"found by a scan on {stamp}",
                              False, None, secrets=secrets, container=container)
        except ValidationError as exc:
            print(f"    not recorded: {exc}")
            continue
        for w in out["warnings"]:
            print(f"    warning: {w}")
        print(f"    {out['result']['ip']} recorded ({out['result']['kind']})")
        done.append(out)
    return done
