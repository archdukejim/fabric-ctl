from webui.devpreview.sample_data import (SAMPLE_ACCESS, SAMPLE_ACME, SAMPLE_CA, SAMPLE_DEVICES, SAMPLE_DHCP,
                                          SAMPLE_DIRECTORY, SAMPLE_DNS_FILTER, SAMPLE_DOMAIN, SAMPLE_FEDERATION,
                                          SAMPLE_GPO,
                                          SAMPLE_IMAGES, SAMPLE_RADIUS, SAMPLE_SECURITY, SAMPLE_VAULT)
from webui.devpreview.sample_radius_guides import sample_radius_guides
from webui.devpreview.sample_settings import SAMPLE_SETTINGS, SAMPLE_SETTINGS_FILE
from webui.devpreview.fabric_rules import ValidationError
from webui.devpreview.fake_directory import kerberos_policy


def _dns_filter(state):
    """Purpose: The DNS filter's sample, or, with the preview's `fresh` toggle, a fresh install's whose first fetch of
             the lists has not finished (the page then refreshes itself, 2.1.2.22).
    Inputs:  state — DevState (toggles).
    Returns: dict, GET /v1/dns-filter's shape.
    Fails:   never.
    Feeds:   fake_reads."""
    if not state.toggles.get("fresh"):
        return SAMPLE_DNS_FILTER
    return {**SAMPLE_DNS_FILTER, "catalogue_fetched": None, "categories": ["Added by URL"],
            "lists": [{**r, "last_fetch": None, "last_success": None, "rules": None, "memory_mb": None}
                      for r in SAMPLE_DNS_FILTER["lists"] if r["category"] == "Added by URL"]}


def _person(state, uid):
    """Purpose: One sample person as GET /v1/people/<uid> answers (manual 1.6.12.4): details, state, last sign-in,
             groups, sites, the certificates issued to them and the devices they own.
    Inputs:  state — DevState; uid — the user name.
    Returns: dict, the agent's shape.
    Fails:   ValidationError "no person <uid> in OU=people" (as the agent).
    Feeds:   fake_reads."""
    row = next((u for u in state.data["people"]["users"] if u["uid"] == uid), None)
    if row is None:
        raise ValidationError(f"no person {uid} in OU=people")
    devices = [{k: d.get(k) for k in ("name", "type", "enabled", "macs", "roles", "vlan")}      # owners as user names
               for d in (state.overview() or {}).get("devices", []) if d.get("owner") == uid]
    certs = ([{"subject": f"CN={uid}", "serial": "1a2b3c", "not_after": "Oct 20 12:00:00 2027 GMT",
               "status": "valid", "kind": "client"}] if uid == "jim" else [])
    return {"uid": uid, "person": dict(row.get("person") or {}), "groups": list(row["groups"]),
            "state": row.get("state") or ("disabled" if row["locked"] else "active"),
            "last_logon": row.get("last_logon") or "", "sites": list(row.get("sites") or []), "certs": certs,
            "devices": devices}


def _sites(state):
    """Purpose: The preview's sites as GET /v1/sites answers (manual 1.6.12.8): its people and computers by their
             sites, the DCs of SAMPLE_DIRECTORY, the help desk's grant on lan, the AD sites fabric would write.
    Inputs:  state — DevState.
    Returns: dict, the agent's shape.
    Fails:   never.
    Feeds:   fake_reads."""
    links = [{"name": "lan-edge", "sites": ["edge", "lan"], "cost": "100", "interval": "15"}]
    ad = {"lan": {"name": "lan", "dcs": ["pi-core"], "subnets": ["192.168.1.0/24"], "links": links},
          "edge": {"name": "edge", "dcs": ["pi-edge"], "subnets": ["192.168.30.0/24"], "links": links}}
    return {"dc_text": "2 DCs used, 1997 can be added", "replication": SAMPLE_DIRECTORY["replication"], "error": "",
            "sites": [{"name": n, "group": f"site-{n}",
                       "people": sorted(u["uid"] for u in state.data["people"]["users"] if n in (u.get("sites") or [])),
                       "machines": sorted(m["name"] for m in SAMPLE_DOMAIN["machines"] if n in (m.get("sites") or [])),
                       "dcs": ["pi-core"] if n == "lan" else ["pi-edge"],
                       "grants": ["lan-helpdesk"] if n == "lan" else [], "ad": ad.get(n)}
                      for n in SAMPLE_DIRECTORY["sites"]]}


def _spns():
    """Purpose: The preview's service principals as GET /v1/domain/kerberos/spns answers (manual 1.6.12.9): each
             computer's HOST names, the sso account's HTTP name, and one name held twice, to show the flag.
    Inputs:  none.
    Returns: dict, the agent's shape.
    Fails:   never.
    Feeds:   fake_reads."""
    rows = [{"spn": f"HOST/{m['dns']}", "account": m["name"].upper() + "$", "kind": "computer"}
            for m in SAMPLE_DOMAIN["machines"]]
    rows += [{"spn": "HTTP/sso.home.arpa", "account": "svc-sso", "kind": "account"},
             {"spn": "HTTP/wiki.home.arpa", "account": "HOST-1$", "kind": "computer"},
             {"spn": "HTTP/wiki.home.arpa", "account": "svc-wiki", "kind": "account"}]
    for r in rows:
        r["duplicate"] = r["spn"] == "HTTP/wiki.home.arpa"
    return {"spns": sorted(rows, key=lambda r: (r["spn"].lower(), r["account"].lower())),
            "duplicates": ["HTTP/wiki.home.arpa"]}


def _dhcp(state):
    """Purpose: DHCP's sample, or, with the preview's `off` toggle, DHCP off as a first turn-on shows it (manual
             1.10.3.5; `off=resume`: off with its settings kept).
    Inputs:  state — DevState (toggles).
    Returns: dict, GET /v1/dhcp's shape.
    Fails:   never.
    Feeds:   fake_reads."""
    off = state.toggles.get("off")
    return SAMPLE_DHCP if not off else {**SAMPLE_DHCP, "enabled": False, "has_settings": off == "resume",
                                        "leases": []}


def fake_reads(state, who, route, body):
    """Purpose: The fake agent's reads: GET /v1/<route> from the preview's sample data, in the agent's shapes.
    Inputs:  state — DevState; who — {"user", "perms"}; route — segments after /v1/; body — unused.
    Returns: the answer, or None for a route it does not know.
    Fails:   ValidationError "no such job" / "no such zone" (as the agent).
    Feeds:   fake_agent."""
    d = state.data
    fixed = {
        ("version",): lambda: {"version": "dev preview", "build": "sample data · no sign-in · nothing is saved",
                               "host": "pi-core", "domain": "home.arpa"},
        ("services",): lambda: [list(s) for s in d["services"]],
        ("host-changes",): lambda: d["host_changes"], ("relaxed-settings",): lambda: d.get("relaxed_settings", []),
        ("cert-warnings",): lambda: d.get("cert_warnings", []), ("reminders",): lambda: [],
        ("images",): lambda: SAMPLE_IMAGES, ("audit",): lambda: d["audit"],
        ("zones",): state.zones, ("reverse-zones",): state.reverse, ("tsig",): lambda: d["tsig"],
        ("dhcp",): lambda: _dhcp(state), ("dns-filter",): lambda: _dns_filter(state),
        ("radius",): lambda: SAMPLE_RADIUS, ("radius", "guides"): sample_radius_guides,
        ("pki", "ca"): lambda: SAMPLE_CA, ("pki", "issued"): lambda: d["issued"], ("pki", "acme"): lambda: SAMPLE_ACME,
        ("devices",): state.overview, ("people",): lambda: d["people"], ("directory",): lambda: SAMPLE_DIRECTORY,
        ("sites",): lambda: _sites(state),
        ("domain", "kerberos"): lambda: {"realm": "AD.HOME.ARPA", "kdcs": ["pi-core", "pi-edge"], "kdcs_error": "",
                                         "policy": kerberos_policy(state),
                                         "signin_kerberos": any(r["layer"] == "kerberos" and r["value"] == "on"
                                                                for r in SAMPLE_SECURITY)},
        ("domain", "kerberos", "spns"): _spns,
        ("domain",): lambda: SAMPLE_DOMAIN, ("gpo",): lambda: {**SAMPLE_GPO, "match": ""},
        ("host-groups",): lambda: SAMPLE_ACCESS["groups"], ("sudo",): lambda: SAMPLE_ACCESS["sudo"],
        ("federation",): lambda: SAMPLE_FEDERATION,
        ("vault",): lambda: SAMPLE_VAULT, ("vault", "devices"): lambda: SAMPLE_DEVICES,
        ("vault", "slots"): lambda: {"slots": d["slots"], "host": "pi-core"},
        ("security",): lambda: SAMPLE_SECURITY, ("settings",): lambda: SAMPLE_SETTINGS,
        ("settings", "export"): lambda: {"text": SAMPLE_SETTINGS_FILE, "name": "fabric-settings.yaml"},
    }
    if tuple(route) in fixed:
        answer = fixed[tuple(route)]()
        if answer is None:              # the devices without fabriclib
            raise ValidationError("the dev preview from the image has no fabriclib; run it from a checkout")
        return answer
    if len(route) == 2 and route[0] == "people":
        return _person(state, route[1])
    if len(route) == 2 and route[0] == "zones":
        if route[1] not in d["zones"]:
            raise ValidationError("no such zone")
        return state.zone(route[1])
    if len(route) == 2 and route[0] == "jobs":
        job = d.setdefault("jobs", {}).get(route[1])
        if job is None:
            raise ValidationError("no such job")
        return job
    return None
