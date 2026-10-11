import os

from fabriclib.common.ask import ask
from fabriclib.common.console import BOLD, NC, YELLOW, heading

# (settings key, default, what enabling it does, what relaxing it costs)
PLAN = [
    ("security.firewall", True,
     "Host firewall: only fabric's ports inbound, from the LAN only (also enforced for Docker-published ports)",
     "every published port (DNS, LDAP, HTTPS, ...) reachable from any network that can route to this host"),
    ("security.docker_daemon_hardening", True,
     "Harden the Docker daemon (no-new-privileges, no inter-container traffic on the default bridge, "
     "no userland proxy, live-restore, bounded logs)",
     "containers may gain privileges via setuid binaries; logs can fill the disk"),
    ("host_join_domain", True,
     "Make this host a member of its domain: fabric admins sign in to it with their domain accounts (local accounts "
     "unchanged; Advanced to change)",
     "fabric admins sign in to this host with local accounts only"),
    ("install_keycloak", True, "Keycloak SSO (+ Postgres), required by the web UI", "no SSO and no web UI"),
    ("install_webui", True, "Fabric web UI at https://fabric.<domain> (Keycloak sign-in)",
     "manage with fabricctl only"),
]


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


def _ca_exists(ctx):
    """Purpose: whether this install already has its CA (its lifetime is then fixed, 2.1.5.6).
    Inputs:  ctx — SetupContext.
    Returns: bool: Step-CA's ca.json exists.
    Fails:   never.
    Feeds:   choose_plan, _ask_ca_lifetime."""
    return os.path.exists(ctx.path("stepca", "data", "config", "ca.json"))


def _ask_ca_lifetime(ctx):
    """Purpose: Advanced plan question: the root CA's lifetime in years (manual 2.1.5.6); asked only before the CA
             exists. The intermediate lives a year less.
    Inputs:  ctx — SetupContext; reads ctx.vars cert_root_ca_days (default 3650). Interactive.
    Returns: None; ctx.vars["cert_root_ca_days"] set (whole years, at least 1, as days). A value that is not a whole
             number of years from 1 to 30 is refused with the reason and asked again.
    Fails:   EOFError from input().
    Feeds:   choose_plan (Advanced)."""
    if _ca_exists(ctx):
        return
    years = round(int(ctx.vars.get("cert_root_ca_days") or 3650) / 365)
    while True:
        answer = ask("setup.ca_years", f"\n  The internal CA's root is valid for how many years (its intermediate a "
                     f"year less; fixed once made)? [{years}] ", str(years))
        if answer.isdigit() and 1 <= int(answer) <= 30:
            ctx.vars["cert_root_ca_days"] = int(answer) * 365
            return
        print(f"    {YELLOW}{answer!r}: a whole number of years, 1 to 30{NC}")


def _ask_host_join_domain(ctx):
    """Purpose: Advanced plan question: whether setup makes this host a member of its own domain (manual 1.6.11.8,
             decision 2.1.6.34; on by default).
    Inputs:  ctx — SetupContext; reads ctx.vars host_join_domain (default True). Interactive.
    Returns: None; ctx.vars["host_join_domain"] set to True or False. An answer other than y, yes, n or no is
             refused with the reason and asked again.
    Fails:   EOFError from input().
    Feeds:   choose_plan (Advanced)."""
    now = ctx.vars.get("host_join_domain", True) is not False
    while True:
        answer = ask("setup.host_join_domain",
                     f"\n  Make this host a member of its domain {'[Y/n]' if now else '[y/N]'} ",
                     "y" if now else "n").lower()
        if answer in ("y", "yes", "n", "no"):
            ctx.vars["host_join_domain"] = answer.startswith("y")
            return
        print(f"    {YELLOW}{answer!r}: answer y or n{NC}")


def _get(data, dotted, default):
    """Purpose: read a dotted key ("security.firewall") from nested dicts.
    Inputs:  data — dict; dotted — key path; default — value when any part is missing or not a dict.
    Returns: the value found, or default.
    Fails:   never.
    Feeds:   choose_plan."""
    node = data
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _set(data, dotted, value):
    """Purpose: write a dotted key into nested dicts, creating intermediate dicts.
    Inputs:  data — dict (modified); dotted — key path; value — value to store.
    Returns: None.
    Fails:   TypeError/AttributeError if an intermediate key holds a non-dict value.
    Feeds:   choose_plan."""
    parts = dotted.split(".")
    node = data
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def choose_plan(ctx):
    """Purpose: show what setup will do (every default is the hardened choice), then Proceed / Advanced / Quit.
             Advanced holds what is best chosen before the install (2.1.2.16): the CA root's lifetime, before the
             CA exists (fixed once made); whether this host becomes a member of its domain (1.6.11.8: undone later
             with `fabricctl setup --undo member`). Everything else shown is a default changed after the install
             (fabricctl, the vars editor; the web console's settings page after 0.7, 2.1.1.42).
    Inputs:  ctx — SetupContext: vars (PLAN keys, install_* flags, log_forwarding, dhcp, radius_clients,
             webui_admin_user), non_interactive, assume_yes. Interactive unless one of those two is set.
    Returns: None. Every PLAN item's effective value is written into ctx.vars (so what was shown is what gets
             rendered), and dns_filter (the BIND resolver on unless set to none, 2.1.12.3); install_webui is forced
             off when Keycloak is off. deploy_config saves ctx.vars to
             fabric.yaml, so a --file can set all of these non-interactively.
    Fails:   SystemExit("setup cancelled") on Quit; EOFError from input().
    Feeds:   run_setup main (full runs only, after collect_vars)."""
    def show():
        heading("fabricctl setup will:")
        for key, default, does, cost in PLAN:
            on = bool(_get(ctx.vars, key, default))
            mark = "✓" if on else f"{YELLOW}✗{NC}"
            print(f"  {mark} {does}" + ("" if on else f"  {YELLOW}(disabled: {key}; {cost}){NC}"))
        print("  ✓ Run every service non-root with no capabilities and a read-only filesystem")
        if _ca_exists(ctx):
            print("  ✓ Keep this install's CA (Step-CA); TLS certificates for every service, renewed every 30 days")
        else:
            years = round(int(ctx.vars.get("cert_root_ca_days") or 3650) / 365)
            print(f"  ✓ Create an internal CA (Step-CA; root valid {years} years, fixed once made — Advanced to "
                  "change) and TLS "
                  "certificates for every service, renewed every 30 days; trust it on this host")
        if _get(ctx.vars, "install_webui", True):
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
            print(f"  ✓ Optional: DHCP with Kea 3.0 on {subnets or '(no subnet yet)'}; hostnames in dhcp.<domain>")
        else:
            print("  · Optional, off: DHCP with Kea (hostnames registered in DNS)")
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

    # Record the effective value of every item, so what was shown is what
    # gets rendered (template defaults differ, e.g. install_keycloak).
    for key, default, _, _ in PLAN:
        _set(ctx.vars, key, bool(_get(ctx.vars, key, default)))
    ctx.vars["dns_filter"] = str(ctx.vars.get("dns_filter") or "bind").lower()
    show()
    if ctx.non_interactive or ctx.assume_yes:
        return
    what = ("the CA's lifetime, this host's domain membership" if not _ca_exists(ctx)
            else "this host's domain membership")
    prompt = f"\n  {BOLD}[P]roceed{NC}, [A]dvanced ({what}), or [Q]uit? "
    while True:
        choice = ask("setup.plan", prompt, "p").lower()
        if choice.startswith("q"):
            raise SystemExit("setup cancelled")
        if choice.startswith("p"):
            return
        if choice.startswith("a"):
            _ask_ca_lifetime(ctx)
            _ask_host_join_domain(ctx)
            show()
