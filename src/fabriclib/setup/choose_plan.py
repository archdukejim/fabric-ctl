from fabriclib.common.ask import ask
from fabriclib.common.console import BOLD, NC, YELLOW, heading
from fabriclib.consent.groups import GROUPS
from fabriclib.consent.load_consent import load_consent
from fabriclib.setup.advanced.setup_menu import setup_menu
from fabriclib.setup.common.ca_exists import ca_exists
from fabriclib.setup.common.dotted_keys import get_dotted
from fabriclib.setup.common.plan_items import PLAN
from fabriclib.setup.errors import SetupError
from fabriclib.setup.finish_vars import finish_vars
from fabriclib.system.show_memory_plan import show_memory_plan

CLOUDFLARE = [{"address": "1.1.1.1", "name": "cloudflare-dns.com"},
              {"address": "1.0.0.1", "name": "cloudflare-dns.com"}]           # vars.yaml.j2's default (2.1.12.3)


def _upstreams_text(ctx):
    """Purpose: how the plan names the DNS filter's internet upstreams.
    Inputs:  ctx — SetupContext; reads ctx.vars dns_filter_upstreams (None: the default).
    Returns: "Cloudflare (DNS-over-TLS)", "the root servers (no forwarder)" or "<address> (<name>)" joined by ", ".
    Fails:   never.
    Feeds:   choose_plan."""
    ups = ctx.vars.get("dns_filter_upstreams")
    if ups is None or list(ups) == CLOUDFLARE:
        return "Cloudflare (DNS-over-TLS)"
    return ", ".join(f"{u.get('address')} ({u.get('name')})" for u in ups) or "the root servers (no forwarder)"


def _show_settings(ctx):
    """Purpose: the plan's first part: what setup will do with the settings chosen (every default the hardened choice).
    Inputs:  ctx — SetupContext (vars, the CA's state).
    Returns: None; prints.
    Fails:   never.
    Feeds:   choose_plan."""
    heading("fabricctl setup will:")
    for key, default, does, cost in PLAN:
        on = bool(get_dotted(ctx.vars, key, default))
        mark = "✓" if on else f"{YELLOW}✗{NC}"
        print(f"  {mark} {does}" + ("" if on else f"  {YELLOW}(disabled: {key}; {cost}){NC}"))
    print("  ✓ Run every service non-root with no capabilities and a read-only filesystem")
    if ca_exists(ctx):
        print("  ✓ Keep this install's CA (Step-CA); TLS certificates for every service, renewed every 30 days")
    else:
        years = round(int(ctx.vars.get("cert_root_ca_days") or 3650) / 365)
        print(f"  ✓ Create an internal CA (Step-CA; root valid {years} years, fixed once made — [M]enu to change) and "
              "TLS certificates for every service, renewed every 30 days; trust it on this host")
    if get_dotted(ctx.vars, "install_webui", True):
        print(f"  ✓ Create the first web UI admin '{ctx.vars.get('webui_admin_user')}' with the password you "
              "chose; login kit in ~/fabric-admin")
    lf = ctx.vars.get("log_forwarding") or {}
    dests = [d for d in ((lf.get("syslog") or {}).get("host"), (lf.get("elastic") or {}).get("url")) if d]
    if ctx.vars.get("dns_filter", "bind") == "bind":
        print("  ✓ DNS filter: fabric's resolver answers DNS on port 53, internet lookups to "
              f"{_upstreams_text(ctx)}, AdGuard's DNS filter list (sudo fabricctl dns-filter status)")
    else:
        print("  · Optional, off: DNS filter (fabric's resolver)")
    if ctx.vars.get("install_kea"):
        subnets = ", ".join(s.get("subnet", "?") for s in (ctx.vars.get("dhcp") or {}).get("subnets") or [])
        print(f"  ✓ Optional, a preview until 0.8.0: DHCP with Kea 3.0 on {subnets or '(no subnet yet)'}; "
              "hostnames in dhcp.<domain>")
    else:
        print("  · Optional, off: DHCP with Kea, a preview until 0.8.0 (hostnames registered in DNS)")
    if ctx.vars.get("install_freeradius"):
        n = len(ctx.vars.get("radius_clients") or [])
        print(f"  ✓ Optional: 802.1X with FreeRADIUS ({n} RADIUS client{'s' if n != 1 else ''})")
    else:
        print("  · Optional, off: 802.1X with FreeRADIUS")
    if ctx.vars.get("install_fluentbit"):
        print(f"  ✓ Optional: forward all logs with Fluent Bit to {', '.join(dests) or '(no destination yet)'}")
    else:
        print("  · Optional, off: forward all logs to syslog / Elasticsearch (Fluent Bit)")
    print("  All of it but the CA can be changed after the install: `sudo fabricctl` opens the settings "
          "(2.1.2.16).")


def _decide(ctx, changes):
    """Purpose: which planned host changes Proceed allows: the required ones always, a recommended one unless turned
             off in the menu (ctx.host_choices), and none whose needed change is off (2.1.2.13).
    Inputs:  ctx — SetupContext (host_choices); changes — {group: [change, ...]} as planned.
    Returns: {group: bool} for every group in changes.
    Fails:   never.
    Feeds:   choose_plan."""
    out = {}
    for group in changes:
        on = ctx.host_choices.get(group, True) if GROUPS[group]["level"] == "recommended" else True
        needs = GROUPS[group].get("needs")
        out[group] = on and (needs not in changes or out.get(needs, False))
    return out


def _show_host_changes(changes, decided, recorded):
    """Purpose: the plan's host changes (manual 1.2.9.11.4): every group that is on, with its changes — a group whose
             changes differ from what was allowed before marked, its new lines with "+" — then the host's own firewall
             rules it removes said apart, one by one, with how to keep them (own_rules, 2.1.2.24) — then those turned
             off, each with what that means.
    Inputs:  changes — {group: [change, ...]}; decided — _decide's result (None: unattended, every group shown as
             planned); recorded — consent.yaml's groups ({group: {answer, changes}}).
    Returns: None; prints.
    Fails:   never.
    Feeds:   choose_plan."""
    heading("Changes to this host outside fabric's own folders" + (" — [P]roceed allows all of these" if decided
                                                                   is not None else ""))
    for group, lines in changes.items():
        if decided is not None and not decided[group]:
            continue
        g, rec = GROUPS[group], recorded.get(group) or {}
        new = [c for c in lines if c not in (rec.get("changes") or [])]
        changed = rec.get("answer") == "yes" and new
        print(f"  {BOLD}{g['title']}{NC} ({g['level']})" + (f"  {YELLOW}changed since it was allowed{NC}" if changed
                                                            else ""))
        for c in lines:
            print(f"    {'+' if changed and c in new else '-'} {c}")
    own = changes.get("own_rules") or []
    if own and (decided is None or decided.get("own_rules")):
        # rules fabric did not add are said apart, one by one, with how to keep them (2.1.2.24)
        print(f"  {YELLOW}{BOLD}Firewall rules of this host's own that fabric will REMOVE ({len(own)}):{NC}")
        for c in own:
            print(f"    {YELLOW}x {c}{NC}")
        print(f"    {YELLOW}To keep them: [M]enu, then turn off '{GROUPS['own_rules']['title']}' "
              f"(unattended: --decline own_rules). Uninstall puts removed ones back.{NC}")
    off = [g for g, on in (decided or {}).items() if not on]
    if off:
        print(f"  {BOLD}Not made{NC} (declined; [M]enu to change):")
        for group in off:
            print(f"    {GROUPS[group]['title']}: {YELLOW}{GROUPS[group]['declined']}{NC}")


def choose_plan(ctx, plan_host):
    """Purpose: show what setup will do, the memory split (1.2.4.3) and every host change (1.2.9.11.4, decisions
             2.1.2.18, 2.1.2.19), then [P]roceed — the one yes allowing every host change listed — [M]enu — the menu
             of every setting (setup_menu), after which the plan shows again — or [Q]uit. Everything else shown is a
             default changed after the install (fabricctl, the vars editor, the web console's settings).
    Inputs:  ctx — SetupContext: vars, host_choices, config_dir (consent.yaml: what was allowed before),
             non_interactive, assume_yes; plan_host — callable() -> (rendered vars, {group: [change, ...]}), the
             settings as they will render and the host changes they plan (raising SetupError when they cannot: a
             memory plan that does not fit, an account id taken).
    Returns: {group: bool} — every planned group, allowed (True) or declined in the menu (False) — on Proceed; None for
             an unattended run or --yes (the plan is shown, nothing asked: --approve / --decline answer).
    Fails:   SystemExit("setup cancelled") on Quit; SetupError from plan_host in an unattended run (interactive: shown,
             and only [M]enu or [Q]uit are offered); EOFError from input().
    Feeds:   setup/run_setup (full runs, after collect_vars and the first admin)."""
    while True:
        _show_settings(ctx)
        try:
            rendered, changes = plan_host()
            problem = ""
        except SetupError as e:
            if ctx.non_interactive or ctx.assume_yes:
                raise
            rendered, changes, problem = None, {}, str(e)
        if rendered is not None:
            show_memory_plan(rendered, "memory fabric may use")
        interactive = not (ctx.non_interactive or ctx.assume_yes)
        decided = _decide(ctx, changes) if interactive else None
        _show_host_changes(changes, decided, load_consent(ctx.config_dir) or {})
        if not interactive:
            return None
        if problem:
            print(f"\n  {YELLOW}setup cannot proceed: {problem}{NC}")
        prompt = ("\n  [M]enu or [Q]uit? " if problem
                  else f"\n  {BOLD}[P]roceed{NC} (allows the host changes listed), [M]enu, or [Q]uit? ")
        while True:
            choice = ask("setup.plan", prompt).lower()        # no default: Proceed is a yes to the host changes
            if choice in ("q", "quit"):
                raise SystemExit("setup cancelled")
            if choice in ("p", "proceed") and not problem:
                return decided
            if choice in ("m", "menu"):
                setup_menu(ctx)
                finish_vars(ctx)
                break
            print(f"    {YELLOW}{choice!r}: answer " + ("m or q" if problem else "p, m or q") + f"{NC}")
