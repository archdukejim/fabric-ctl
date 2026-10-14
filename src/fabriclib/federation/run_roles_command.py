from fabriclib.common.errors import ValidationError
from fabriclib.federation.change_site_role import change_site_role
from fabriclib.federation.remake_site_group import remake_site_group
from fabriclib.federation.site_roles import site_roles


def _show(v, only):
    """Purpose: print the roles at this site and the sites below it, one line per role that anyone holds.
    Inputs:  v — fabric vars; only — a site's name, or "" for every site shown.
    Returns: 0.
    Fails:   ValidationError from site_roles, or "no site <only> here: …" for a site not shown.
    Feeds:   run_roles_command."""
    sites = site_roles(v)["sites"]
    if only:
        sites = [s for s in sites if s["site"].lower() == only.lower()]
        if not sites:
            raise ValidationError(f"no site {only} here: this site shows itself and the sites below it")
    for s in sites:
        held = [r for r in s["roles"] if r["members"]]
        mark = " (this site: only a site above grants its roles)" if s["own"] else ""
        print(f"site {s['site']}{mark}: {len(held)} role(s) held; {s['site']}-admins is its helpdesk")
        for r in held:
            what = f"bundle {r['bundle']}" if r["kind"] == "console" else "AD role"
            note = "  (an older default: the next convergence takes it away)" if r["pending"] else ""
            print(f"  {r['role']:<20} {what:<34} {', '.join(r['members'])}{note}")
        for m in s.get("misplaced") or []:     # 2.1.9.24: reported, never moved
            print(f"  MISPLACED {m['uid']} lives at {m['lives']} but holds a role at {', '.join(sorted(m['holds']))}:"
                  f" move it from a site above (fabricctl people move {m['uid']} --site {sorted(m['holds'])[0]})")
    return 0


def run_roles_command(v, args, actor="root"):
    """Purpose: `fabricctl federation roles [<site>] | grant <site> <role> [--to M] | revoke <site> <role> [--from M]
             | remake <site> <role|admins>` (manual 4.9.1.2, 2.1.9.21): show the roles granted at this site and the
             sites below it, grant one at a site below, take it back, or make a site below's group again. Only routes.
    Inputs:  v — fabric vars; args — list of str after `roles`; actor — the audit's name (the CLI runs as root).
    Returns: exit status: 0 done; 2 usage (the caller prints it).
    Fails:   ValidationError from site_roles or change_site_role (the caller prints it, exit 1).
    Feeds:   federation/run_federation_command (`roles`)."""
    if args[:1] == ["remake"] and len(args) == 3:
        done = remake_site_group(v, actor, args[1], args[2], source="cli")
        what = ("replaced: the site had made it itself" if done["remade"] else "made: it was missing"
                if done["made"] else "left as it is: fabric made it")
        print(f"group {done['group']} at {done['site']} {what}"
              + ("; it gets its rights at the next convergence" if done["changed"] else ""))
        return 0
    if len(args) <= 1 and (not args or args[0] not in ("grant", "revoke", "remake")):
        return _show(v, args[0] if args else "")
    if args[0] in ("grant", "revoke") and len(args) in (3, 5):
        flag = "--to" if args[0] == "grant" else "--from"
        if len(args) == 5 and args[3] != flag:
            return 2
        done = change_site_role(v, actor, args[1], args[2], args[4] if len(args) == 5 else "", args[0] == "grant",
                                source="cli")
        state = "granted to" if done["granted"] else "revoked from"
        print(f"{done['role']} at {done['site']} {state} {done['member']} (group {done['group']})"
              + ("" if done["changed"] else " — no change")
              + ("; remade: the group the site had made itself was replaced (2.1.9.21)" if done.get("remade") else ""))
        return 0
    return 2
