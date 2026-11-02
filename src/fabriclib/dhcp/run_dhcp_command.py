import getpass
import sys

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.dhcp.add_client_class import add_client_class
from fabriclib.dhcp.add_reservation import add_reservation
from fabriclib.dhcp.add_subnet import add_subnet
from fabriclib.dhcp.clean_dhcp_names import clean_dhcp_names
from fabriclib.dhcp.dhcp_overview import dhcp_overview
from fabriclib.dhcp.kea_key.rotate_key import rotate_key
from fabriclib.dhcp.common.apply_dhcp_change import apply_dhcp_change
from fabriclib.dhcp.list_leases import list_leases
from fabriclib.dhcp.remove_client_class import remove_client_class
from fabriclib.dhcp.remove_reservation import remove_reservation
from fabriclib.dhcp.remove_subnet import remove_subnet
from fabriclib.dhcp.run_dhcp_alias import ALIASES, run_dhcp_alias
from fabriclib.dhcp.set_dhcp_on import set_dhcp_on
from fabriclib.dhcp.set_option import set_option
from fabriclib.dhcp.unset_option import unset_option
from fabriclib.dhcp.update_subnet import KEEP, update_subnet
from fabriclib.ipam.common.plan_holds_subnets import plan_holds_subnets

USAGE = """usage: fabricctl dhcp status                       subnets (name, VLAN, notes), pools, options, classes
       fabricctl dhcp on [--interface I --subnet N --pool "a - b" [--router IP]]
                                                   turn DHCP on (the first subnet when it has none yet)
       fabricctl dhcp off                          turn DHCP off (its settings and leases are kept)
       fabricctl dhcp leases                       active leases (from Kea)
       fabricctl dhcp reserve <mac> <ip> [<hostname>]
       fabricctl dhcp unreserve <mac>
       fabricctl dhcp add-subnet <network> --name N [--vlan V] [--router IP] [--pool "a - b"]... [--notes T]
                                 [--allow-overlap "<why>"]
       fabricctl dhcp set-subnet <name|network> [--name N] [--vlan V|none] [--router IP|none] [--notes T]
                                 [--add-pool "a - b"]... [--remove-pool "a - b"]... [--allow-overlap "<why>"|none]
       fabricctl dhcp remove-subnet <name|network> [--force]
       fabricctl dhcp option set <name|code> <data> [--subnet S | --class C | --mac M] [--always-send]
       fabricctl dhcp option unset <name|code> [--subnet S | --class C | --mac M]
       fabricctl dhcp class add <name> --test "<Kea expression>" [--next-server IP] [--boot-file F]
       fabricctl dhcp class remove <name>
       fabricctl dhcp clean-names [--scheduled]   delete DHCP names left behind for addresses named by hand
                                                   (also hourly, by fabric-dhcp-names.timer: 2.1.10.22)
       fabricctl dhcp rotate-key                   replace Kea's DNS key now, then apply (an apply replaces it
                                                   once it is 330 days old: 2.1.10.42)
   every change applies at once unless --no-apply
   once this site's subnets live in the address plan, add-subnet, set-subnet, remove-subnet, reserve and unreserve
   are aliases of fabricctl ipam (for one release; --name and --vlan of set-subnet are refused)"""
FLAGS = {"--name", "--vlan", "--router", "--pool", "--notes", "--add-pool", "--remove-pool", "--subnet", "--class",
         "--mac", "--test", "--next-server", "--boot-file", "--allow-overlap", "--interface"}


def _parse(args):
    """Purpose: split command arguments into positionals and --flag values (repeatable flags keep every value).
    Inputs:  args — list of str.
    Returns: (positionals, {flag: [values]}, set of bare flags such as --force).
    Fails:   ValidationError for a value flag without a value.
    Feeds:   run_dhcp_command."""
    pos, vals, bare, i = [], {}, set(), 0
    while i < len(args):
        a = args[i]
        if a in FLAGS:
            if i + 1 >= len(args):
                raise ValidationError(f"{a} needs a value")
            vals.setdefault(a, []).append(args[i + 1])
            i += 2
            continue
        if a.startswith("--"):
            bare.add(a)
        else:
            pos.append(a)
        i += 1
    return pos, vals, bare


def _vlan(text):
    """Purpose: a --vlan value: a number, or none to clear.
    Inputs:  text — str.
    Returns: int, or None for "none".
    Fails:   ValidationError for anything else.
    Feeds:   run_dhcp_command."""
    if text.lower() == "none":
        return None
    if not text.isdigit():
        raise ValidationError(f"--vlan {text}: a number from 1 to 4094, or none")
    return int(text)


def _show(d):
    """Purpose: print `fabricctl dhcp status`.
    Inputs:  d — dhcp_overview's result (DHCP on).
    Returns: None.
    Fails:   never.
    Feeds:   run_dhcp_command."""
    print(f"interfaces {', '.join(d['interfaces'])}  lease {d['lease_time']} s"
          + (f"  hostnames in {d['ddns_zone']}" if d["ddns_zone"] else ""))
    for o in d["options"]:
        print(f"option {o.get('name', o.get('code'))} = {o['data']}  (every subnet)")
    if d["overrides"]:
        print(f"replaces fabric's own: {', '.join(d['overrides'])}")
    for s in d["subnets"]:
        label = " ".join(x for x in (s.get("name") or "", f"VLAN {s['vlan']}" if s.get("vlan") else "") if x)
        print(f"{s['subnet']:<20} {label:<20} pools {', '.join(s.get('pools') or []) or '-'}  "
              f"router {s.get('routers') or '-'}")
        if s.get("notes"):
            print(f"  notes: {s['notes']}")
        for o in s.get("options") or []:
            print(f"  option {o.get('name', o.get('code'))} = {o['data']}")
        for r in s.get("reservations") or []:
            print(f"  {r['mac']}  {r['ip']:<15} {r.get('hostname') or ''}")
    for c in d["client_classes"]:
        boot = " ".join(f"{k}={c[k]}" for k in ("next_server", "boot_file_name") if c.get(k))
        print(f"class {c['name']}: {c['test']}  {boot}")
        for o in c.get("options") or []:
            print(f"  option {o.get('name', o.get('code'))} = {o['data']}")


def _keep(one, flag):
    """Purpose: a set-subnet value: KEEP when the flag is absent, None for "none", else the text.
    Inputs:  one — {flag: last value}; flag — e.g. "--router".
    Returns: KEEP, None or str.
    Fails:   never.
    Feeds:   run_dhcp_command (set-subnet)."""
    if flag not in one:
        return KEEP
    return None if one[flag].lower() == "none" else one[flag]


def run_dhcp_command(v, argv):
    """Purpose: `fabricctl dhcp …` — the Kea tab's operations without the web UI: status, leases, reservations,
             subnets (name, VLAN record, notes, router, pools), options at every level, client classes (manual
             1.10.2.5); `clean-names`, the DHCP names left behind for addresses named by hand (1.10.4.20); and
             `rotate-key`, Kea's DNS key replaced now (rotate_key, 1.10.4.43). Once
             this site's subnets live in the address plan, add-subnet, set-subnet, remove-subnet,
             reserve and unreserve are aliases of `fabricctl ipam` (run_dhcp_alias, 1.10.4.21, 1.10.4.37).
    Inputs:  v — the rendered vars (SetupContext.load_state().vars); argv — list of str after "dhcp" (default
             status); see USAGE. Every change applies at once unless --no-apply.
    Returns: exit status: 0 success; 1 a ValidationError, unreadable leases or a failed apply; 2 usage (printed to
             stderr).
    Fails:   ValidationError is caught (exit 1); other exceptions propagate.
    Feeds:   fabriclib/cli.py (`fabricctl dhcp`)."""
    cmd, args = (argv[0], argv[1:]) if argv else ("status", [])
    try:
        pos, vals, bare = _parse(args)
        one = {k: x[-1] for k, x in vals.items()}
        where = {"subnet": one.get("--subnet"), "client_class": one.get("--class"), "mac": one.get("--mac")}
        if cmd in ALIASES and plan_holds_subnets(load_vars()):     # aliases of fabricctl ipam (1.10.4.21)
            status = run_dhcp_alias(v, cmd, pos, one, vals, bare, args)
            if status is not None:
                return status
            print(USAGE, file=sys.stderr)
            return 2
        if cmd in ("status", "leases") and not pos:
            d = dhcp_overview(v)
            if not d["enabled"]:
                print("DHCP is off (install_kea: false)")
                return 0
            if cmd == "status":
                _show(d)
                return 0
            if d["leases_error"]:
                print(f"error: {d['leases_error']}", file=sys.stderr)
                return 1
            for lease in d["leases"]:
                print(f"{lease['ip']:<15} {lease['mac']}  {lease['hostname'] or '-':<30} {lease['expires']}  "
                      f"{lease['state']}")
            return 0
        if cmd in ("on", "off") and not pos:
            r = set_dhcp_on("root", cmd == "on", one.get("--interface", ""), one.get("--subnet", ""),
                            one.get("--pool", ""), one.get("--router", ""), source="cli")
            print(f"DHCP {cmd}" + (f": {', '.join(r['subnets'])} on {', '.join(r['interfaces'])}" if r["on"] else
                                   " (its settings and leases kept)"))
            return apply_dhcp_change(args)
        if cmd == "reserve" and len(pos) in (2, 3):
            saved = add_reservation("root", pos[0], pos[1], pos[2] if len(pos) == 3 else "", source="cli")
            print(f"reserved {saved['ip']} for {saved['mac']}")
            return apply_dhcp_change(args)
        if cmd == "unreserve" and len(pos) == 1:
            remove_reservation("root", pos[0], source="cli")
            print(f"reservation for {pos[0]} removed")
            return apply_dhcp_change(args)
        if cmd == "add-subnet" and len(pos) == 1 and "--name" in one:
            s = add_subnet("root", pos[0], one["--name"], _vlan(one["--vlan"]) if "--vlan" in one else None,
                           one.get("--router"), vals.get("--pool", []), one.get("--notes", ""),
                           one.get("--allow-overlap", ""), source="cli")
            print(f"subnet {s['subnet']} ({s['name']}, id {s['id']}) added")
            return apply_dhcp_change(args)
        if cmd == "set-subnet" and len(pos) == 1:
            s = update_subnet("root", pos[0], name=_keep(one, "--name"),
                              vlan=KEEP if "--vlan" not in one else _vlan(one["--vlan"]),
                              router=_keep(one, "--router"), notes=one.get("--notes", KEEP),
                              add_pools=vals.get("--add-pool", []), remove_pools=vals.get("--remove-pool", []),
                              allow_overlap=_keep(one, "--allow-overlap"), source="cli")
            print(f"subnet {s['subnet']} changed")
            return apply_dhcp_change(args)
        if cmd == "remove-subnet" and len(pos) == 1:
            try:
                leases = list_leases(v) if v.get("install_kea") else []
            except ValidationError:
                leases = None                    # Kea not answering: cannot tell, so --force is needed
            print(f"subnet {remove_subnet('root', pos[0], leases, force='--force' in bare, source='cli')} removed")
            return apply_dhcp_change(args)
        if cmd == "option" and pos[:1] == ["set"] and len(pos) == 3:
            label, o = set_option("root", pos[1], pos[2], always_send=True if "--always-send" in bare else None,
                                  source="cli", **where)
            print(f"option {o.get('name', o.get('code'))} set for {label}")
            return apply_dhcp_change(args)
        if cmd == "option" and pos[:1] == ["unset"] and len(pos) == 2:
            print(f"option {pos[1]} removed from {unset_option('root', pos[1], source='cli', **where)}")
            return apply_dhcp_change(args)
        if cmd == "class" and pos[:1] == ["add"] and len(pos) == 2 and "--test" in one:
            add_client_class("root", pos[1], one["--test"], one.get("--next-server"), one.get("--boot-file"),
                             source="cli")
            print(f"client class {pos[1]} added (options: fabricctl dhcp option set ... --class {pos[1]})")
            return apply_dhcp_change(args)
        if cmd == "clean-names" and not pos and not vals and bare <= {"--scheduled"}:
            r = clean_dhcp_names(v, getpass.getuser(), "timer" if bare else "cli")
            if "off" in r:
                print(r["off"])
                return 0
            for owner, rtype, rdata in r["removed"]:
                print(f"deleted {owner.rstrip('.')} {rtype} {rdata}")
            print(f"DHCP names left behind: {len(r['removed'])} record(s) deleted")
            return 0
        if cmd == "rotate-key" and not pos and not vals and not bare:
            r = rotate_key(v, getpass.getuser())
            print(r["started"] or "a replacement of Kea's DNS key was under way: this apply finishes it")
            print("applied: Kea runs on the new key; BIND dropped the old one" if r["ok"] else r["output"])
            return 0 if r["ok"] else 1
        if cmd == "class" and pos[:1] == ["remove"] and len(pos) == 2:
            remove_client_class("root", pos[1], source="cli")
            print(f"client class {pos[1]} removed")
            return apply_dhcp_change(args)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(USAGE, file=sys.stderr)
    return 2
