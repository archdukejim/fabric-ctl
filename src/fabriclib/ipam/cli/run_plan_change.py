from fabriclib.ipam.add_address import add_address
from fabriclib.ipam.add_range import add_range
from fabriclib.ipam.add_subnet import add_subnet
from fabriclib.ipam.add_vlan import add_vlan
from fabriclib.ipam.cli.args import keep, on_off
from fabriclib.ipam.cli.report_change import report_change
from fabriclib.ipam.common.vlan_refs import vlan_label
from fabriclib.ipam.remove_address import remove_address
from fabriclib.ipam.remove_range import remove_range
from fabriclib.ipam.remove_subnet import remove_subnet
from fabriclib.ipam.remove_vlan import remove_vlan
from fabriclib.ipam.set_address import set_address
from fabriclib.ipam.set_block import set_block
from fabriclib.ipam.set_subnet import set_subnet
from fabriclib.ipam.set_vlan import set_vlan


def _subnet_line(out):
    """Purpose: what `vlan add` and `subnet add` print for the subnet they added and its ranges.
    Inputs:  out — add_vlan's or add_subnet's result (subnet, ranges).
    Returns: list of str.
    Fails:   never.
    Feeds:   run_plan_change."""
    sub = out["subnet"]
    return ([f"  subnet {sub['name']}: {sub['cidr']}, gateway {sub['gateway'] or '-'}"] if sub else []) + [
        f"  {rng['kind']} {rng['first']} - {rng['last']}" for rng in out["ranges"]]


def _vlan(v, sub, rest, vals, bare, site, common):
    """Purpose: `vlan add|set|remove`.
    Inputs:  as run_plan_change, with sub the subcommand and rest its positionals.
    Returns: exit status, or None when the arguments are not a VLAN command.
    Fails:   ValidationError from the plan's functions.
    Feeds:   run_plan_change."""
    if sub == "add" and len(rest) == 1 and "--name" in vals:
        out = add_vlan(v, "root", rest[0], vals["--name"], site, vals.get("--subnet", ""),
                       "--no-subnet" in bare, vals.get("--gateway", ""), vals.get("--purpose", ""),
                       vals.get("--notes", ""), vals.get("--access", "full"),
                       on_off(vals["--dhcp"], "--dhcp") if "--dhcp" in vals else True, vals.get("--relay", ""),
                       vals.get("--allow-overlap", ""), "--no-split" not in bare, **common)
        r = out["result"]
        if r["block_set"]:
            print(f"site {out['site']} given the number {r['block_set']} (its order in the organisation)")
        print(f"{vlan_label(r['vlan'])} ({r['vlan']['name']}) added"
              + (f": {r['subnet']['cidr']}, gateway {r['subnet']['gateway'] or '-'}" if r["subnet"] else ""))
        for rng in r["ranges"]:
            print(f"  {rng['kind']} {rng['first']} - {rng['last']}")
        return report_change(v, out, bare)
    if sub == "set" and len(rest) == 1:
        out = set_vlan(v, "root", rest[0], site, name=keep(vals, "--name"), purpose=keep(vals, "--purpose"),
                       notes=keep(vals, "--notes"), access=keep(vals, "--access"),
                       gateway=keep(vals, "--gateway", clear=True),
                       dhcp=keep(vals, "--dhcp", convert=on_off), relay=keep(vals, "--relay", clear=True),
                       allow_overlap=keep(vals, "--allow-overlap", clear=True),
                       to_location=keep(vals, "--to-location", clear=True), **common)
        print(f"{vlan_label(out['result']['vlan'])} changed")
        return report_change(v, out, bare)
    if sub == "remove" and len(rest) == 1:
        out = remove_vlan(v, "root", rest[0], site, "--force" in bare, **common)
        print(f"{vlan_label(out['result']['vlan'])} removed"
              + (f" with {out['result']['subnet']}" if out["result"]["subnet"] else ""))
        return report_change(v, out, bare)
    return None


def _subnet(v, sub, rest, vals, bare, site, common):
    """Purpose: `subnet add|set|remove`.
    Inputs:  as run_plan_change, with sub the subcommand and rest its positionals.
    Returns: exit status, or None when the arguments are not a subnet command.
    Fails:   ValidationError from the plan's functions.
    Feeds:   run_plan_change."""
    if sub == "add" and len(rest) == 2:
        out = add_subnet(v, "root", rest[0], rest[1], site, vals.get("--name", ""), vals.get("--gateway", ""),
                         on_off(vals["--dhcp"], "--dhcp") if "--dhcp" in vals else True, vals.get("--relay", ""),
                         vals.get("--notes", ""), vals.get("--allow-overlap", ""), "--no-split" not in bare,
                         **common)
        print(f"{vlan_label(out['result']['vlan'])} has a new subnet")
        print("\n".join(_subnet_line(out["result"])))
        return report_change(v, out, bare)
    if sub == "set" and len(rest) == 1:
        out = set_subnet(v, "root", rest[0], site, gateway=keep(vals, "--gateway", clear=True),
                         dhcp=keep(vals, "--dhcp", convert=on_off), relay=keep(vals, "--relay", clear=True),
                         notes=keep(vals, "--notes"), allow_overlap=keep(vals, "--allow-overlap", clear=True),
                         **common)
        print(f"subnet {out['result']['name']} ({out['result']['cidr']}) changed")
        return report_change(v, out, bare)
    if sub == "remove" and len(rest) == 1:
        out = remove_subnet(v, "root", rest[0], site, "--force" in bare, **common)
        s = out["result"]["subnet"]
        print(f"subnet {s['name']} ({s['cidr']}) removed" + (f" with {out['result']['addresses']} address(es)"
                                                            if out["result"]["addresses"] else ""))
        return report_change(v, out, bare)
    return None


def _address(v, cmd, sub, rest, vals, bare, site, common):
    """Purpose: `range add|remove` and `address add|set|remove` (the two kinds of record inside a subnet).
    Inputs:  as run_plan_change, with cmd "range" or "address", sub the subcommand and rest its positionals.
    Returns: exit status, or None when the arguments are not such a command.
    Fails:   ValidationError from the plan's functions.
    Feeds:   run_plan_change."""
    if cmd == "range" and sub == "add" and len(rest) == 4:
        out = add_range(v, "root", rest[0], rest[1], rest[2], rest[3], site, vals.get("--notes", ""), **common)
        print(f"{out['result']['kind']} range {out['result']['first']} - {out['result']['last']} added")
        return report_change(v, out, bare)
    if cmd == "range" and sub == "remove" and len(rest) == 2:
        out = remove_range(v, "root", rest[0], rest[1], site, **common)
        print(f"{out['result']['kind']} range {out['result']['first']} - {out['result']['last']} removed")
        return report_change(v, out, bare)
    if cmd == "address" and sub == "add" and len(rest) == 1 and "--kind" in vals:
        out = add_address(v, "root", rest[0], vals["--kind"], site, vals.get("--name", ""), vals.get("--mac", ""),
                          vals.get("--owner", ""), vals.get("--notes", ""),
                          on_off(vals["--dns"], "--dns") if "--dns" in vals else False,
                          vals.get("--vlan"), **common)
        print(f"{out['result']['ip']} recorded ({out['result']['kind']})")
        return report_change(v, out, bare)
    if cmd == "address" and sub == "set" and len(rest) == 1:
        out = set_address(v, "root", rest[0], site, kind=keep(vals, "--kind"),
                          name=keep(vals, "--name", clear=True), mac=keep(vals, "--mac", clear=True),
                          owner=keep(vals, "--owner"), notes=keep(vals, "--notes"),
                          dns=keep(vals, "--dns", convert=on_off), **common)
        print(f"{out['result']['ip']} changed")
        return report_change(v, out, bare)
    if cmd == "address" and sub == "remove" and len(rest) == 1:
        out = remove_address(v, "root", rest[0], site, **common)
        print(f"{out['result']['ip']} removed")
        return report_change(v, out, bare)
    return None


def run_plan_change(v, cmd, pos, vals, bare, site, secrets=None, container="samba"):
    """Purpose: `fabricctl ipam block <n>` and `vlan|subnet|range|address add|set|remove` (manual 1.10.4.16): each the
             plan's function it names, run as root (acting for the Enterprise Admin), its result printed, then
             applied here or left to the other site's poll (report_change). Routes only.
    Inputs:  v — the rendered vars; cmd — the command; pos — its positionals; vals, bare — the flags (parse_args);
             site — --site's value ("" this site); secrets, container — as the plan's functions.
    Returns: exit status, or None when cmd and its arguments are not a change (the caller prints the usage).
    Fails:   ValidationError from the plan's functions (the caller prints it, exit 1).
    Feeds:   ipam/run_ipam_command."""
    common = {"secrets": secrets, "container": container}
    if cmd == "block" and len(pos) == 1:
        out = set_block(v, "root", pos[0], site, **common)
        r = out["result"]
        print(f"site {out['site']} is number {r['block']}" + (f" (was {r['was']})" if r["was"] else "")
              + ": what fabric suggests from now on is 10." + str(r["block"])
              + ".<VLAN>.0/24; subnets already in the plan keep their networks")
        return 0
    sub, rest = (pos[0], pos[1:]) if pos else ("", [])
    if cmd == "vlan":
        return _vlan(v, sub, rest, vals, bare, site, common)
    if cmd == "subnet":
        return _subnet(v, sub, rest, vals, bare, site, common)
    if cmd in ("range", "address"):
        return _address(v, cmd, sub, rest, vals, bare, site, common)
    return None
