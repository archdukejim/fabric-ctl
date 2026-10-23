from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.common.apply_dhcp_change import apply_dhcp_change
from fabriclib.ipam.add_address import add_address
from fabriclib.ipam.add_dhcp_subnet import add_dhcp_subnet
from fabriclib.ipam.common.fields import KEEP
from fabriclib.ipam.remove_reservation_mac import remove_reservation_mac
from fabriclib.ipam.remove_subnet import remove_subnet
from fabriclib.ipam.set_dhcp_subnet import set_dhcp_subnet

# the 0.7 commands that are aliases of `fabricctl ipam` once the subnets live in the plan (manual 1.10.4.21,
# 1.10.4.37: 0.8.0's commands, the same)
ALIASES = {"add-subnet": "ipam vlan add / subnet add", "set-subnet": "ipam subnet set / range add|remove",
           "remove-subnet": "ipam subnet remove", "reserve": "ipam address add --kind reservation",
           "unreserve": "ipam address remove"}


def _clear(one, flag):
    """Purpose: a set-subnet value: KEEP when the flag is absent, "" for "none", else the text.
    Inputs:  one — {flag: last value}; flag — e.g. "--router".
    Returns: KEEP, "" or str.
    Fails:   never.
    Feeds:   run_dhcp_alias."""
    if flag not in one:
        return KEEP
    return "" if one[flag].lower() == "none" else one[flag]


def run_dhcp_alias(v, cmd, pos, one, vals, bare, args):
    """Purpose: 0.7's subnet commands once this site's subnets live in the address plan (manual 1.10.4.9,
             1.10.4.21, decision 2.1.10.27): each an alias of the `fabricctl ipam` change it stands for, for one
             release, saying so; every rule is the plan's. Routes only.
             add-subnet <network> --name N [--vlan V] [--router IP] [--pool "a - b"]... [--notes T]
             [--allow-overlap W] -> add_dhcp_subnet; set-subnet <name|network> [--router IP|none] [--notes T]
             [--add-pool]... [--remove-pool]... [--allow-overlap W|none] -> set_dhcp_subnet (--name and --vlan
             refused: a subnet's name and VLAN stay in the plan); remove-subnet <name|network> [--force] ->
             remove_subnet (--force: with its recorded addresses); reserve <mac> <ip> [<hostname>] -> add_address
             (a reservation); unreserve <mac> -> remove_reservation_mac.
    Inputs:  v — rendered vars; cmd — the 0.7 command; pos — positionals; one — {flag: last value}; vals — {flag:
             [values]}; bare — bare flags; args — the raw arguments (--no-apply).
    Returns: exit status (apply_dhcp_change's), or None when the arguments are not a form this alias knows (the
             caller prints the usage).
    Fails:   ValidationError from the ipam functions (the caller prints it, exit 1); what apply_dhcp_change raises.
    Feeds:   dhcp/run_dhcp_command."""
    vlan = one.get("--vlan")
    if cmd == "add-subnet" and len(pos) == 1 and "--name" in one:
        if vlan is not None and not vlan.isdigit():
            raise ValidationError(f"--vlan {vlan}: a number from 1 to 4094")
        out = add_dhcp_subnet(v, "root", pos[0], one["--name"], int(vlan) if vlan else None, one.get("--router"),
                              vals.get("--pool", []), one.get("--notes", ""), one.get("--allow-overlap", ""))
        r = out["result"]
        print(f"(alias of fabricctl {ALIASES[cmd]}) subnet {r['subnet']['cidr']} ({r['subnet']['name']}) on VLAN "
              f"{r['vlan']['id']}" + (" (a new VLAN)" if r["vlan_added"] else ""))
    elif cmd == "set-subnet" and len(pos) == 1:
        if "--name" in one or "--vlan" in one:
            raise ValidationError("a subnet's name and VLAN stay in the address plan: remove it and add it again "
                                  "(fabricctl ipam subnet remove / subnet add), or rename its VLAN (ipam vlan set)")
        out = set_dhcp_subnet(v, "root", pos[0], router=_clear(one, "--router"),
                              notes=one.get("--notes", KEEP), allow_overlap=_clear(one, "--allow-overlap"),
                              add_pools=vals.get("--add-pool", []), remove_pools=vals.get("--remove-pool", []))
        print(f"(alias of fabricctl {ALIASES[cmd]}) subnet {out['result']['name']} changed")
    elif cmd == "remove-subnet" and len(pos) == 1:
        out = remove_subnet(v, "root", pos[0], "", "--force" in bare)
        print(f"(alias of fabricctl {ALIASES[cmd]}) subnet {out['result']['subnet']['cidr']} removed")
    elif cmd == "reserve" and len(pos) in (2, 3):
        out = add_address(v, "root", pos[1], "reservation", "", pos[2] if len(pos) == 3 else "", pos[0])
        print(f"(alias of fabricctl {ALIASES[cmd]}) reserved {out['result']['ip']} for {out['result']['mac']}")
    elif cmd == "unreserve" and len(pos) == 1:
        out = remove_reservation_mac(v, "root", pos[0])
        print(f"(alias of fabricctl {ALIASES[cmd]}) reservation {out['result']['ip']} for {pos[0]} removed")
    else:
        return None
    for w in out["warnings"]:
        print(f"warning: {w}")
    return apply_dhcp_change(args)
