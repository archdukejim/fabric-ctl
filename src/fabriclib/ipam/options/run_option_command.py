import sys

from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.common.apply_dhcp_change import apply_dhcp_change
from fabriclib.ipam.options.add_plan_class import add_plan_class
from fabriclib.ipam.options.clear_netboot import clear_netboot
from fabriclib.ipam.options.define_plan_option import define_plan_option
from fabriclib.ipam.options.options_overview import options_overview
from fabriclib.ipam.options.remove_plan_class import remove_plan_class
from fabriclib.ipam.options.remove_plan_option import remove_plan_option
from fabriclib.ipam.options.set_netboot import set_netboot
from fabriclib.ipam.options.set_plan_option import set_plan_option
from fabriclib.ipam.options.show_netboot import show_netboot
from fabriclib.ipam.options.show_options import show_options
from fabriclib.ipam.options.undefine_plan_option import undefine_plan_option

USAGE = """usage: fabricctl ipam option show [domain | site | subnet <name|cidr> | address <ip>]
       fabricctl ipam option set <scope> <name|code> <data> [--always-send] [--csv off] [--space S]
       fabricctl ipam option remove <scope> <name|code> [--space S]
           <scope>: domain | site | subnet <name|cidr> | class <name> [--domain] | address <ip>
       fabricctl ipam option define domain|site <name> <code> <type> [--array] [--record-types T] [--space S]
       fabricctl ipam option undefine domain|site <name> [--space S]
       fabricctl ipam class add domain|site <name> --test EXPR [--next-server IP] [--server-hostname N]
                               [--boot-file F]
       fabricctl ipam class remove domain|site <name>
       fabricctl ipam netboot show <vlan|subnet|ip>
       fabricctl ipam netboot on <vlan|subnet|ip> --server ADDRESS|NAME [--bios F] [--uefi F] [--arm64 F]
                               [--ipxe URL] [--http URL]
       fabricctl ipam netboot off <vlan|subnet|ip>
   --site S: another site's options (any site your grants' networks options right reaches; the domain's set needs
   it at all sites, manual 1.6.13.12); `org` and --org, 0.8's words, read as `domain` and --domain; a change to
   this site's plan or to the domain's set applies here at once unless --no-apply"""
FLAGS = {"--site", "--csv", "--space", "--record-types", "--test", "--next-server", "--server-hostname",
         "--boot-file", "--server", "--bios", "--uefi", "--arm64", "--ipxe", "--http"}
BARE = {"--always-send", "--array", "--domain", "--org", "--no-apply"}
TARGETED = ("subnet", "class", "address")


def _parse(args):
    """Purpose: split arguments into positionals, --flag values and bare flags (--org read as --domain).
    Inputs:  args — list of str.
    Returns: (positionals, {flag: value}, set of bare flags).
    Fails:   ValidationError for a value flag without a value, or an unknown flag.
    Feeds:   run_option_command."""
    pos, vals, bare, i = [], {}, set(), 0
    while i < len(args):
        a = args[i]
        if a in FLAGS:
            if i + 1 >= len(args):
                raise ValidationError(f"{a} needs a value")
            vals[a] = args[i + 1]
            i += 2
            continue
        if a.startswith("--"):
            if a not in BARE:
                raise ValidationError(f"unknown option {a}")
            bare.add("--domain" if a == "--org" else a)
        else:
            pos.append(a)
        i += 1
    return pos, vals, bare


def _scope(pos):
    """Purpose: a scope and its target off the front of the positionals.
    Inputs:  pos — positionals after set/remove.
    Returns: (scope, target, the rest).
    Fails:   ValidationError for a missing scope or target.
    Feeds:   run_option_command."""
    if not pos:
        raise ValidationError("give where: domain, site, subnet <name>, class <name> or address <ip>")
    if pos[0] in TARGETED:
        if len(pos) < 2:
            raise ValidationError(f"{pos[0]}: give its name")
        return pos[0], pos[1], pos[2:]
    return pos[0], "", pos[1:]


def _done(v, out, bare, lines):
    """Purpose: report a change and apply it here when it is this site's plan (or the domain's set).
    Inputs:  v — fabric vars; out — edit_options' result; bare — bare flags (--no-apply); lines — what to print.
    Returns: exit status (apply_dhcp_change's for this site, 0 for another).
    Fails:   what apply_dhcp_change raises.
    Feeds:   run_option_command."""
    for line in lines:
        print(line)
    for w in out.get("warnings") or []:
        print(f"warning: {w}")
    if out["site"] != v.get("site_name"):
        print(f"written to {out['site']}'s plan: it takes effect at that site's next apply")
        return 0
    return apply_dhcp_change(["--no-apply"] if "--no-apply" in bare else [])


def run_option_command(v, cmd, args, secrets=None, container="samba"):
    """Purpose: `fabricctl ipam option | class | netboot` (manual 1.10.4.24.5, 1.10.4.25, 1.10.4.26; Volume 4:
             4.10.2.10, 4.10.2.11), run as root, acting for the Enterprise Admin. Routes only: every rule is in the
             function each command calls.
    Inputs:  v — the rendered vars; cmd — "option", "class" or "netboot"; args — the arguments after it; secrets —
             fabric's secrets (default loaded by the functions); container — the DC's container. See USAGE.
    Returns: exit status: 0 success (and help); 1 a refusal (printed with why) or a failed apply; 2 usage.
    Fails:   ValidationError is caught (exit 1); other exceptions propagate.
    Feeds:   ipam/run_ipam_command."""
    if args[:1] in (["--help"], ["-h"], ["help"]):
        print(USAGE)
        return 0
    common = {"secrets": secrets, "container": container}
    try:
        pos, vals, bare = _parse(args)
        site = vals.get("--site", "")
        sub, rest = (pos[0], pos[1:]) if pos else ("", [])
        if cmd == "option" and sub == "show":
            target = ""
            if rest == ["site"]:
                target = "site"
            elif rest and rest[0] in ("subnet", "address") and len(rest) == 2:
                target = f"{rest[0]}:{rest[1]}"
            elif rest and rest not in (["domain"], ["org"]):
                raise ValidationError("option show: domain, site, subnet <name> or address <ip>")
            print(show_options(options_overview(v, site, target, **common)), end="")
            return 0
        if cmd == "option" and sub == "set":
            scope, target, more = _scope(rest)
            if len(more) != 2:
                raise ValidationError("option set <scope> <name|code> <data>")
            csv = vals.get("--csv")
            if csv not in (None, "on", "off"):
                raise ValidationError("--csv is on or off")
            out = set_plan_option(v, "root", scope, target, more[0], more[1], site, "--domain" in bare,
                                  True if "--always-send" in bare else None,
                                  None if csv is None else csv == "on", vals.get("--space"), **common)
            r = out["result"]
            return _done(v, out, bare, [f"{r['where']}: option {r['code'] or '-'} {r['name']} = {r['option']['data']}"])
        if cmd == "option" and sub == "remove":
            scope, target, more = _scope(rest)
            if len(more) != 1:
                raise ValidationError("option remove <scope> <name|code>")
            out = remove_plan_option(v, "root", scope, target, more[0], site, "--domain" in bare,
                                     vals.get("--space"), **common)
            r = out["result"]
            return _done(v, out, bare, [f"{r['where']}: option {r['code'] or '-'} {r['name']} removed"])
        if cmd == "option" and sub == "define" and len(rest) == 4:
            out = define_plan_option(v, "root", rest[0], rest[1], rest[2], rest[3], "--array" in bare,
                                     vals.get("--record-types", ""), vals.get("--space"), site, **common)
            d = out["result"]
            return _done(v, out, bare, [f"option {d['name']} defined: code {d['code']}, {d['type']}"])
        if cmd == "option" and sub == "undefine" and len(rest) == 2:
            out = undefine_plan_option(v, "root", rest[0], rest[1], vals.get("--space"), site, **common)
            return _done(v, out, bare, [f"option {out['result']['name']} no longer defined"])
        if cmd == "class" and sub == "add" and len(rest) == 2 and "--test" in vals:
            out = add_plan_class(v, "root", rest[0], rest[1], vals["--test"], vals.get("--next-server", ""),
                                 vals.get("--server-hostname", ""), vals.get("--boot-file", ""), site, **common)
            return _done(v, out, bare, [f"client class {out['result']['name']} added"])
        if cmd == "class" and sub == "remove" and len(rest) == 2:
            out = remove_plan_class(v, "root", rest[0], rest[1], site, **common)
            return _done(v, out, bare, [f"client class {out['result']['name']} removed"])
        if cmd == "netboot" and sub == "show" and len(rest) == 1:
            print(show_netboot(options_overview(v, site, **common), rest[0]), end="")
            return 0
        if cmd == "netboot" and sub == "on" and len(rest) == 1:
            preset = {k: vals.get(f"--{k}", "") for k in ("server", "bios", "uefi", "arm64", "ipxe", "http")}
            out = set_netboot(v, "root", rest[0], preset, site, **common)
            return _done(v, out, bare, [f"netboot on: {', '.join(out['result']['targets'])}"])
        if cmd == "netboot" and sub == "off" and len(rest) == 1:
            out = clear_netboot(v, "root", rest[0], site, **common)
            return _done(v, out, bare, [f"netboot off: {', '.join(out['result']['targets'])}"])
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(USAGE, file=sys.stderr)
    return 2
