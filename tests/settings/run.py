#!/usr/bin/env python3
"""The `settings` suite, the setup wizard's model with no container (manual 1.8.5.9, decision 2.1.8.7): the settings
file's round trip (export, import, the same settings); the keys an import ignores, listed by reason (a secret, console
only, not a setting); every wizard key refused with its reason when invalid, nothing changed; the plan (each change old
to new, the parts started or stopped, the memory plan); a stale plan refused at apply; the apply written under the
lock and audited, the host's own log-forwarding keys kept; the wizard's fields both ways; `fabricctl settings` export
and import, positive and negative. The settings, the lock, the apply and the audit log are stood in for (pure logic:
the global Rule 9 allows it); the sandbox applies a wizard change end to end.

    python3 tests/settings/run.py
"""
import copy
import io
import json
import os
import sys
import tempfile
from contextlib import contextmanager, redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
import yaml  # noqa: E402

from fabriclib.common.errors import ValidationError  # noqa: E402
import fabriclib.settings.apply_settings as m_apply  # noqa: E402
import fabriclib.settings.mark_wizard_finished as m_mark  # noqa: E402
import fabriclib.settings.run_settings_command as m_cmd  # noqa: E402
from fabriclib.samba.check_password_policy import DEFAULT_POLICY  # noqa: E402
from fabriclib.settings.check_wizard_value import check_wizard_value  # noqa: E402
from fabriclib.settings.constants import WIZARD_KEYS  # noqa: E402
from fabriclib.settings.export_settings import export_settings  # noqa: E402
from fabriclib.settings.form_from_settings import form_from_settings  # noqa: E402
from fabriclib.settings.parse_settings_file import parse_settings_file  # noqa: E402
from fabriclib.settings.plan_is_current import plan_is_current  # noqa: E402
from fabriclib.settings.plan_settings import plan_settings  # noqa: E402
from fabriclib.settings.read_settings import read_settings  # noqa: E402
from fabriclib.settings.settings_from_form import settings_from_form  # noqa: E402
from fabriclib.settings.wizard_finished import wizard_finished  # noqa: E402

FAILED = 0
V = {"site_name": "home", "hostname": "pi-core", "domain": "home.arpa", "ad_domain": "ad.home.arpa",
     "host_ip": "192.168.1.10", "lan_cidr": "192.168.1.0/24", "lan_gateway": "192.168.1.1",
     "install_keycloak": True, "install_webui": True, "install_kea": False, "dns_filter": "bind",
     "install_fluentbit": False, "log_forwarding": {}, "host_ram_capacity": 8,
     "ad_password_policy": dict(DEFAULT_POLICY), "signin_kerberos": False,
     "logon_policies": {"machines": {"console": ["home-machine-admins"], "remote": ["home-machine-admins"]}},
     "dns_filter_upstreams": [{"address": "9.9.9.9", "name": "dns.quad9.net"}], "webui_admin_user": "fabric-admin"}


def check(name, ok, detail=""):
    global FAILED
    FAILED += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


def refused(fn, words):
    try:
        fn()
    except ValidationError as e:
        return words in str(e) or str(e)
    return "not refused"


def plan(given, v=None, ignored=(), source="web"):
    return plan_settings(copy.deepcopy(v or V), given, ignored, source=source, have_gb=8)


# ---- the settings file: export, then import, gives the same settings
exp = export_settings(V, "0.8.0")
doc = yaml.safe_load(exp["text"])
check("export: fabric_settings 1, from the site and version, every wizard key and nothing else",
      doc["fabric_settings"] == 1 and doc["from"] == {"site": "home", "version": "0.8.0"}
      and list(doc["settings"]) == list(WIZARD_KEYS) and exp["name"] == "home-settings.yaml", doc)
check("export: no console-only setting and no secret in the file",
      "host_ip" not in exp["text"] and "webui_admin_user" not in exp["text"] and "password:" not in exp["text"])
parsed = parse_settings_file(exp["text"], known=V)
check("import of an export: every wizard key taken, nothing ignored",
      list(parsed["settings"]) == list(WIZARD_KEYS) and parsed["ignored"] == [], parsed["ignored"])
p = plan(parsed["settings"])
check("round trip: the exported file's plan changes nothing", p["changes"] == [] and p["keys"] == [], p["changes"])
lf_host = {**V, "log_forwarding": {"syslog": {"host": "logs.example.org", "port": 6514, "ca_file": "/etc/ssl/x.pem"},
                                    "hosts": {"logs.example.org": "192.168.1.5"}}}
exp2 = yaml.safe_load(export_settings(lf_host, "0.8.0")["text"])["settings"]["log_forwarding"]
check("export: log forwarding without what names something on the host (ca_file, hosts)",
      exp2 == {"syslog": {"host": "logs.example.org", "port": 6514}}, exp2)

# ---- import: what it ignores, and why
text = yaml.safe_dump({"fabric_settings": 1, "settings": {
    "dns_filter": "none", "webui_oidc_secret": "s3cret", "ad_admin_password": "x", "tsig_keys": [],
    "host_ip": "10.0.0.1", "domain": "evil.example", "webui_client_cert": False, "favourite_colour": "blue"}})
parsed = parse_settings_file(text, known=V)
why = {i["key"]: i["reason"] for i in parsed["ignored"]}
check("import: secrets ignored as a secret", why.get("webui_oidc_secret") == "a secret"
      and why.get("ad_admin_password") == "a secret" and why.get("tsig_keys") == "a secret", why)
check("import: the network, the identity and the client certificate ignored as console only",
      why.get("host_ip") == "console only" and why.get("domain") == "console only"
      and why.get("webui_client_cert") == "console only", why)
check("import: an unknown key ignored as not a setting", why.get("favourite_colour") == "not a setting", why)
check("import: only the wizard's key taken", parsed["settings"] == {"dns_filter": "none"}, parsed["settings"])
parsed_dhcp = parse_settings_file(yaml.safe_dump({"fabric_settings": 1, "settings": {
    "install_kea": True, "dhcp": {"interfaces": ["eth0"]}, "dns_filter": "none"}}), known={**V, "dhcp": {}})
why = {i["key"]: i["reason"] for i in parsed_dhcp["ignored"]}
check("import: DHCP is not the wizard's in 0.8.0 (2.1.1.58): install_kea and dhcp ignored as console only",
      parsed_dhcp["settings"] == {"dns_filter": "none"} and why.get("install_kea") == "console only"
      and why.get("dhcp") == "console only" and "install_kea" not in WIZARD_KEYS and "dhcp" not in WIZARD_KEYS, why)
p = plan(parsed["settings"], ignored=parsed["ignored"], source="file")
check("the plan carries the ignored list and where it came from", p["ignored"] == parsed["ignored"]
      and p["source"] == "file" and [c["key"] for c in p["changes"]] == ["dns_filter"], p)

# covers: cli:settings.import -
check("refused: not YAML", refused(lambda: parse_settings_file("a: [b"), "not YAML") is True)
check("refused: not a map", refused(lambda: parse_settings_file("- a\n- b\n"), "no map") is True)
check("refused: no fabric_settings", refused(lambda: parse_settings_file("settings: {}\n"),
                                             "fabric_settings: 1") is True)
check("refused: another format version, named", refused(lambda: parse_settings_file(
    "fabric_settings: 2\nsettings: {}\n"), "it has 2") is True)
check("refused: no settings map", refused(lambda: parse_settings_file("fabric_settings: 1\nsettings: [1]\n"),
                                          "no `settings:` map") is True)

# ---- every wizard key refused with its reason, nothing changed
BAD = [
    ("dns_filter", "adguard", "dns_filter: bind"),
    ("install_fluentbit", 1, "install_fluentbit: true or false"),
    ("log_forwarding", {"syslog": {"host": "bad host!", "port": 514}}, "log_forwarding.syslog"),
    ("log_forwarding", {"elastic": {"url": "http://es.example.org"}}, "https://"),
    ("log_forwarding", {"syslog": {"host": "logs.example.org", "ca_file": "/etc/shadow"}}, "console only"),
    ("log_forwarding", {"hosts": {"a": "1.2.3.4"}}, "console only"),
    ("log_forwarding", {"kafka": {}}, "only syslog, elastic"),
    ("host_ram_capacity", 2, "host_ram_capacity: a whole number of GB, 4 to 8"),
    ("host_ram_capacity", 64, "4 to 8"),
    ("host_ram_capacity", "8", "host_ram_capacity"),
    ("ad_password_policy", {"minimum_length": 200}, "minimum_length must be a whole number from 0 to 64"),
    ("ad_password_policy", {"colour": 1}, "unknown keys"),
    ("ad_password_policy", "strong", "ad_password_policy: a map"),
    ("signin_kerberos", "on", "signin_kerberos: true or false"),
    ("logon_policies", {"machines": {"console": [], "remote": []}}, "grants nobody"),
    ("logon_policies", {"linux": {"console": ["g"]}}, "no policy on the site's OU"),
    ("dns_filter_upstreams", [], "at least one"),
    ("dns_filter_upstreams", [{"address": "not-an-ip", "name": "dns.quad9.net"}], "needs an IP address"),
    ("dns_filter_upstreams", "9.9.9.9", "a list of {address, name}"),
]
seen = set()
for key, value, words in BAD:
    before = copy.deepcopy(V)
    why = refused(lambda: plan({key: value}), words)
    seen.add(key)
    check(f"refused: {key} = {value!r}, saying why, the settings unchanged", why is True and V == before, why)
check("every wizard key has a refusal", seen == set(WIZARD_KEYS), set(WIZARD_KEYS) - seen)
check("refused as a whole: one invalid value among valid ones changes nothing", refused(
    lambda: plan({"dns_filter": "none", "host_ram_capacity": 99}), "host_ram_capacity") is True)
check("refused: log forwarding on with nowhere to send the logs", refused(
    lambda: plan({"install_fluentbit": True}), "needs somewhere to send the logs") is True)
try:
    check_wizard_value("install_kea", True, V, 8)
    not_wizard = "accepted"
except KeyError:
    not_wizard = True
check("refused: install_kea is not a wizard key in 0.8.0 (DHCP stays setup's, 2.1.1.58)", not_wizard is True,
      not_wizard)
check("refused: the parts on do not fit the memory (plan_memory's reason)", refused(
    lambda: plan({"host_ram_capacity": 4, "install_fluentbit": True,
                  "log_forwarding": {"syslog": {"host": "logs.example.org", "port": 6514}}},
                 {**V, "memory_floors": {"keycloak": 3000}}), "host_ram_capacity: memory:") is True)

# ---- the plan
SYSLOG = {"syslog": {"host": "logs.example.org", "port": 6514}}
p = plan({"install_fluentbit": True, "log_forwarding": SYSLOG, "host_ram_capacity": 6, "signin_kerberos": True})
ch = {c["key"]: (c["old"], c["new"]) for c in p["changes"]}
check("the plan: each change old -> new, in the wizard's order",
      [c["key"] for c in p["changes"]] == ["install_fluentbit", "log_forwarding", "host_ram_capacity",
                                           "signin_kerberos"]
      and ch["install_fluentbit"] == ("off", "on") and ch["host_ram_capacity"] == ("8", "6"), p["changes"])
check("the plan: Fluent Bit started", p["parts"] == [{"service": "Fluent Bit", "change": "started"}], p["parts"])
rows = {r["service"]: r for r in p["memory"]["rows"]}
check("the plan: the memory plan before and after, Fluent Bit new, Keycloak's share smaller",
      p["memory"]["budget_mb"] == 6 * 1024 - 512 and rows["Fluent Bit"]["before"] is None
      and rows["Keycloak"]["after"] < rows["Keycloak"]["before"], p["memory"])
p2 = plan({"dns_filter": "none"})
check("the plan: the DNS filter off stops its resolver and AdGuard Home",
      {x["service"] for x in p2["parts"]} == {"the DNS filter's resolver", "AdGuard Home (the DNS filter's lists)"}
      and all(x["change"] == "stopped" for x in p2["parts"]), p2["parts"])
p3 = plan({"signin_kerberos": True})
check("the plan: no part and no memory change, no memory plan", p3["memory"] is None and p3["parts"] == [], p3)
p5 = plan({"ad_password_policy": {"minimum_length": 14}})
check("the plan: a partial password policy over today's", p5["settings"]["ad_password_policy"] == {
    **DEFAULT_POLICY, "minimum_length": 14} and p5["keys"] == ["ad_password_policy"], p5["settings"])

# ---- stale, and the apply
check("a plan is current against the settings it was made from", plan_is_current(p3, V, 8))
check("someone applied first: stale", not plan_is_current(p3, {**V, "dns_filter": "none"}, 8))
SAVED, AUDIT, RUNS = [], [], []
STORE = {"v": None}


@contextmanager
def no_lock():
    yield


m_apply.vars_lock = no_lock
m_apply.load_vars = lambda: copy.deepcopy(STORE["v"])
m_apply.save_vars = lambda data: SAVED.append(copy.deepcopy(data))
m_apply.write_audit = lambda actor, action, detail, source="cli": AUDIT.append((actor, action, detail, source))
m_mark.write_audit = lambda actor, action, detail, source="cli": AUDIT.append((actor, action, detail, source))
tmp = tempfile.mkdtemp()


def run_apply(pl, ok=True, **kw):
    def fake(actor, source):
        RUNS.append(("apply", actor, source))
        return ok, "applied output"
    return m_apply.apply_settings(pl, "alice", have_gb=8, apply=fake, config_dir=tmp, **kw)


STORE["v"] = {**V, "dns_filter": "none"}
n = len(SAVED), len(AUDIT), len(RUNS)
check("apply of a stale plan: refused, nothing saved, audited or applied",
      refused(lambda: run_apply(p3), "someone else applied first") is True and (len(SAVED), len(AUDIT), len(RUNS)) == n)
STORE["v"] = copy.deepcopy(V)
res = run_apply(p)
saved = SAVED[-1]
check("apply: the changed keys written, one apply, DHCP left as it was",
      res["ok"] and saved["install_fluentbit"] is True and saved["log_forwarding"] == SYSLOG
      and saved["host_ram_capacity"] == 6 and saved["signin_kerberos"] is True and saved["install_kea"] is False
      and "dhcp" not in saved and RUNS[-1] == ("apply", "alice", "web"), (res, RUNS[-1:]))
check("apply: audited SETTINGS_CHANGE with who, from where and the keys",
      AUDIT[-1][:2] == ("alice", "SETTINGS_CHANGE") and AUDIT[-1][2].startswith("from web: install_fluentbit"),
      AUDIT[-1])
check("apply: the wizard marked finished (applied)", wizard_finished(tmp)["how"] == "applied")
STORE["v"] = copy.deepcopy(lf_host)
pl = plan_settings(copy.deepcopy(lf_host), {"log_forwarding": {"syslog": {"host": "logs2.example.org", "port": 514}}},
                   have_gb=8)
run_apply(pl)
check("apply: the host's own log-forwarding keys kept (ca_file, hosts)", SAVED[-1]["log_forwarding"] == {
    "syslog": {"host": "logs2.example.org", "port": 514, "ca_file": "/etc/ssl/x.pem"},
    "hosts": {"logs.example.org": "192.168.1.5"}}, SAVED[-1]["log_forwarding"])
STORE["v"] = copy.deepcopy(V)
res = run_apply(plan({"dns_filter": "none"}), ok=False)
check("apply that does not finish: saved, said so, not ok", not res["ok"] and "did not finish" in res["message"])

# ---- the wizard's fields, both ways
form = form_from_settings(read_settings(V, 8))
check("fields from today's settings: back to the same settings (nothing changes)",
      plan(settings_from_form(form, read_settings(V, 8)))["keys"] == [], form)
given = settings_from_form({**form, "install_kea": "true", "dhcp_subnet": "192.168.1.0/24",
                            "log_target": "logs.example.org", "install_fluentbit": "true",
                            "logon_policies": "site | admins | admins\nmachines/linux | ops |",
                            "dns_filter_upstreams": "1.1.1.1 one.one.one.one, 9.9.9.9 dns.quad9.net"},
                           read_settings(V, 8))
check("fields: a syslog server (port 6514), log-on lines, upstream pairs; DHCP's fields not read (0.9.0)",
      "install_kea" not in given and "dhcp" not in given and given["log_forwarding"] == {
          "syslog": {"host": "logs.example.org", "port": 6514}}
      and given["logon_policies"] == {"site": {"console": ["admins"], "remote": ["admins"]},
                                      "machines/linux": {"console": ["ops"], "remote": []}}
      and given["dns_filter_upstreams"][0] == {"address": "1.1.1.1", "name": "one.one.one.one"}, given)
for fields, words in (({"host_ram_capacity": "lots"}, "host_ram_capacity: a whole number"),
                      ({"install_fluentbit": "maybe"}, "install_fluentbit: yes or no"),
                      ({"log_target": "http://x.example"}, "https://"),
                      ({"logon_policies": "machines admins"}, "logon_policies"),
                      ({"dns_filter_upstreams": "9.9.9.9"}, "an address and the name"),
                      ({"policy_history": "-1"}, "policy_history: a whole number")):
    check(f"fields refused: {fields}", refused(lambda: settings_from_form(fields, read_settings(V, 8)), words) is True)

# ---- `fabricctl settings`
d = tempfile.mkdtemp()
vars_file = os.path.join(d, "vars.yaml")
with open(vars_file, "w") as f:
    yaml.safe_dump(V, f)
m_cmd.version_info = lambda: {"version": "0.8.0"}
m_cmd.plan_settings = lambda v, given, ignored=(), source="web": plan_settings(v, given, ignored, source, 8)
APPLIED = []


def fake_apply(pl, actor):
    APPLIED.append((pl["keys"], pl["source"], actor))
    return {"ok": True, "keys": pl["keys"], "message": "Applied: " + ", ".join(pl["keys"]) + ".", "output": "ok"}


m_cmd.apply_settings = fake_apply


def cli(*argv, answer=None):
    o, e = io.StringIO(), io.StringIO()
    if answer is not None:
        m_cmd.ask_yes_no = lambda qid, q, now: answer
    with redirect_stdout(o), redirect_stderr(e):
        code = m_cmd.run_settings_command(list(argv), vars_file)
    return code, o.getvalue(), e.getvalue()


# covers: cli:settings cli:settings.export +
code, o, e = cli("export")
check("fabricctl settings export: the file on stdout (exit 0)", code == 0 and "fabric_settings: 1" in o, (code, e))
out = os.path.join(d, "site.yaml")
code, o, e = cli("export", out)
check("fabricctl settings export FILE: written 0600, says how to import it", code == 0
      and oct(os.stat(out).st_mode & 0o777) in ("0o600", "0o666", "0o777") and "settings import" in o, (code, o))
# covers: cli:settings cli:settings.export -
code, o, e = cli("export", out, "extra")
check("fabricctl settings export with two files: the usage (exit 2)", code == 2 and "usage" in e, code)
code, o, e = cli("frobnicate")
check("fabricctl settings with another word: the usage (exit 2)", code == 2 and "fabricctl settings import" in e)
# covers: cli:settings.import +
with open(out, "w") as f:
    f.write(yaml.safe_dump({"fabric_settings": 1, "settings": {"dns_filter": "none", "webui_oidc_secret": "x"}}))
code, o, e = cli("import", out, "--yes")
check("fabricctl settings import FILE --yes: the plan, the ignored key and why, applied from cli (exit 0)",
      code == 0 and "dns_filter: bind -> none" in o and "ignored: webui_oidc_secret (a secret)" in o
      and APPLIED[-1][:2] == (["dns_filter"], "cli") and "Applied" in o, (code, o, e))
# covers: ask:settings.import.apply +
n = len(APPLIED)
code, o, e = cli("import", out, answer=True)
check("import asked and answered yes: applied", code == 0 and len(APPLIED) == n + 1, (code, o, e))
# covers: ask:settings.import.apply -
code, o, e = cli("import", out, answer=False)
check("import asked and answered no: nothing changed (exit 0)", code == 0 and len(APPLIED) == n + 1
      and "Nothing changed" in o, (code, o))
with open(out, "w") as f:
    f.write(yaml.safe_dump({"fabric_settings": 1, "settings": {"host_ram_capacity": 3}}))
code, o, e = cli("import", out, "--yes")
check("fabricctl settings import of an invalid value: refused, the key and why, nothing changed (exit 1)",
      code == 1 and "host_ram_capacity" in e and "nothing changed" in e and len(APPLIED) == n + 1, (code, e))
code, o, e = cli("import", os.path.join(d, "missing.yaml"))
check("fabricctl settings import of a missing file: refused (exit 1)", code == 1 and "cannot read" in e, e)
code, o, e = cli("import")
check("fabricctl settings import without a file: the usage (exit 2)", code == 2, code)
with open(out, "w") as f:
    f.write(export_settings(V, "0.8.0")["text"])
code, o, e = cli("import", out, "--yes")
check("fabricctl settings import of what is already so: nothing changes, no apply (exit 0)",
      code == 0 and "nothing changes" in o and len(APPLIED) == n + 1, (o, e))

# ---- the wizard's record
d2 = tempfile.mkdtemp()
check("not finished before it is applied or dismissed", wizard_finished(d2)["finished"] is False)
rec = m_mark.mark_wizard_finished("dismissed", "bob", config_dir=d2)
check("dismissed: finished, audited", wizard_finished(d2)["how"] == "dismissed" and rec["by"] == "bob"
      and AUDIT[-1][1] == "SETTINGS_DISMISS")
check("a later apply keeps the first record", m_mark.mark_wizard_finished("applied", "carol", config_dir=d2)["how"]
      == "dismissed" and json.load(open(os.path.join(d2, "settings-wizard.json")))["by"] == "bob")

print(f"\n{FAILED} failed" if FAILED else "\nall passed")
sys.exit(1 if FAILED else 0)
