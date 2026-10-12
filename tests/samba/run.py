"""The `samba` suite (manual 1.6.5.13, 3.1.2): the Windows domain controller.

S1.2: the settings check (2.1.6.11, 2.1.6.13), the Administrator's password, the rendered container (host network, exactly the
six capabilities, read-only, its limit), nginx giving up 389/636, the unit and the certificate target.
Real containers (provisioning, DLZ, refusals) are added with S1.3-S1.5.
    python3 tests/samba/run.py
"""
import copy
import os
import string
import sys

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.deploy.check_samba_settings import check_samba_settings  # noqa: E402
from fabriclib.deploy.service_units import service_units  # noqa: E402
from fabriclib.dns_filter.common.filter_zones import filter_zones as adguard_zones  # noqa: E402
from fabriclib.samba.suggested_ad_domain import suggested_ad_domain  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {detail}")


def refused(v, words):
    try:
        check_samba_settings(v)
    except ValidationError as e:
        return words in str(e)
    return False


POLICY = {"minimum_length": 14, "complexity": True, "history": 24, "minimum_age_days": 1, "maximum_age_days": 365,
          "lockout_threshold": 5, "lockout_minutes": 15, "lockout_window_minutes": 15}
GOOD = {"ad_domain": "ad.lan.test", "domain": "lan.test", "hostname": "pi-core", "dc_name": "dc-pi-core",
        "ad_netbios": "AD", "ad_password_policy": POLICY, "ad_old_password_minutes": 0, "ad_rpc_ports": "49152-49251"}

print("--- settings (2.1.6.11, 2.1.6.13)")
try:
    check_samba_settings(copy.deepcopy(GOOD))
    check("a complete configuration passes", True)
except ValidationError as e:
    check("a complete configuration passes", False, e)
# covers: setting:ad_domain -
check("refused: no AD domain (it has no default)", refused({**GOOD, "ad_domain": ""}, "ad_domain is required"))
check("refused: an AD domain of one label", refused({**GOOD, "ad_domain": "ad"}, "not a valid DNS domain"))
check("refused: fabric's own domain (same-domain mode dropped, 2.1.6.11)",
      refused({**GOOD, "ad_domain": "lan.test"}, "cannot be fabric's own domain"))
check("accepted: any other domain, not only the suggested ad.<domain>",
      not refused({**GOOD, "ad_domain": "corp.example.net"}, ""))
check("refused: a parent of fabric's domain", refused({**GOOD, "ad_domain": "test.x", "domain": "lan.test.x"},
                                                       "parent of fabric's domain"))
# covers: setting:ad_netbios -
check("refused: a NetBIOS domain name over 15 characters",
      refused({**GOOD, "ad_netbios": "A" * 16}, "at most 15"))
# covers: setting:dc_name -
check("refused: a DC name Windows cannot use as its NetBIOS name (2.1.6.45)",
      refused({**GOOD, "dc_name": "a-very-long-dc-name"}, "1-15 letters")
      and refused({**GOOD, "dc_name": "dc_1"}, "1-15 letters") and refused({**GOOD, "dc_name": "-dc"}, "hyphen")
      and refused({**GOOD, "dc_name": "12345"}, "only digits") and refused({**GOOD, "dc_name": ""}, "1-15"))
check("refused: the domain's own NetBIOS name as the DC's", refused({**GOOD, "dc_name": "ad"}, "NetBIOS name"))
check("accepted: a long host name: the DC has its own name now (2.1.6.45)",
      not refused({**GOOD, "hostname": "a-very-long-host-name"}, ""))
# covers: setting:ad_password_policy -
check("refused: no password policy (no defaults, 2.1.6.13)",
      refused({**GOOD, "ad_password_policy": {}}, "no defaults"))
check("refused: one policy key missing, named",
      refused({**GOOD, "ad_password_policy": {k: x for k, x in POLICY.items() if k != "history"}}, "history"))
check("refused: an unknown policy key", refused({**GOOD, "ad_password_policy": {**POLICY, "colour": 1}}, "unknown"))
check("refused: complexity that is not true or false",
      refused({**GOOD, "ad_password_policy": {**POLICY, "complexity": "yes"}}, "true or false"))
check("refused: a minimum length over 64 (the Administrator's generated password must fit)",
      refused({**GOOD, "ad_password_policy": {**POLICY, "minimum_length": 65}}, "minimum_length"))
check("refused: a minimum age not below the maximum",
      refused({**GOOD, "ad_password_policy": {**POLICY, "minimum_age_days": 365}}, "must be below the second"))
check("refused: a lockout shorter than its reset window (AD refuses it)",
      refused({**GOOD, "ad_password_policy": {**POLICY, "lockout_minutes": 5}}, "at least as long as that window"))
# covers: setting:ad_password_policy +
check("accepted: locked until an admin unlocks (lockout 0) with any window",
      not refused({**GOOD, "ad_password_policy": {**POLICY, "lockout_minutes": 0}}, ""))
check("accepted: passwords that never expire (maximum 0) with any minimum age",
      not refused({**GOOD, "ad_password_policy": {**POLICY, "maximum_age_days": 0}}, ""))
# covers: setting:ad_rpc_ports -
check("refused: an RPC range at or below 1024", refused({**GOOD, "ad_rpc_ports": "100-200"}, "ad_rpc_ports"))

check("the suggestion is a sibling at the top of the organisation's name (2.1.6.11); a two-label domain gets ad.<it>",
      suggested_ad_domain("lan.j-j.family") == "ad.j-j.family" and suggested_ad_domain("pitest.home.arpa")
      == "ad.home.arpa" and suggested_ad_domain("home.arpa") == "ad.home.arpa"
      and suggested_ad_domain("example.org") == "ad.example.org" and suggested_ad_domain("lan") == "")
check("the two-label suggestion is a valid AD domain (a sub-domain, never the domain or a parent)",
      not refused({**GOOD, "domain": "home.arpa", "ad_domain": suggested_ad_domain("home.arpa")}, ""))
check("accepted: a sub-domain of fabric's domain too", not refused({**GOOD, "ad_domain": "ad.lan.test"}, ""))
check("accepted: the suggested sibling", not refused({**GOOD, "ad_domain": "ad.test2", "domain": "lan.test2"}, ""))

print("--- what setup asks of the directory: only the AD domain; the policy starts from the default (2.1.2.16)")
import builtins  # noqa: E402
import contextlib  # noqa: E402
import io  # noqa: E402
import types  # noqa: E402

from fabriclib.samba.check_password_policy import DEFAULT_POLICY, check_password_policy  # noqa: E402
from fabriclib.setup.ask_ad_domain import ask_ad_domain  # noqa: E402


def ask(answers):
    """setup's directory question with these answers; the AD domain set and what was printed."""
    feed, real = iter(answers), builtins.input
    ctx = types.SimpleNamespace(vars={"domain": "lan.test"})
    builtins.input = lambda prompt="": (print(prompt), next(feed))[1]
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            ask_ad_domain(ctx)
    finally:
        builtins.input = real
    return ctx.vars, out.getvalue()


got, said = ask(["lan.test", ""])
check("only the AD domain is asked: fabric's own domain refused, Enter takes the suggestion; no policy question",
      got == {"domain": "lan.test", "ad_domain": "ad.lan.test"} and "a domain of two labels or more" in said
      and "password" not in said.lower(), (got, said))
try:
    check_password_policy(dict(DEFAULT_POLICY))
    ok_default = True
except ValidationError as e:
    ok_default = str(e)
check("the default policy (2.1.6.35): 12 characters, complexity, 5 remembered, never expires, 10 failures in 15 "
      "minutes lock for 15; AD takes it", ok_default is True and DEFAULT_POLICY == {
          "minimum_length": 12, "complexity": True, "history": 5, "minimum_age_days": 0, "maximum_age_days": 0,
          "lockout_threshold": 10, "lockout_window_minutes": 15, "lockout_minutes": 15}, ok_default)

print("--- the DC's own name (2.1.6.45, manual 1.6.5.23): asked, dc-<hostname> suggested, permanent")
from fabriclib.setup.ask_dc_name import ask_dc_name  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402


def ask_dc(answers, have=None, unattended=False):
    """setup's DC-name question with these answers; the settings after it and what was printed (or the refusal)."""
    feed, real = iter(answers), builtins.input
    ctx = types.SimpleNamespace(vars={"hostname": "Pi-Core", "ad_domain": "ad.lan.test", **(have or {})},
                                non_interactive=unattended)
    builtins.input = lambda prompt="": (print(prompt), next(feed))[1]
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            ask_dc_name(ctx)
    except SetupError as e:
        return None, str(e)
    finally:
        builtins.input = real
    return ctx.vars.get("dc_name"), out.getvalue()


got, said = ask_dc([""])
check("asked with dc-<hostname> suggested; Enter takes it; marked permanent in its one line (2.1.2.21)",
      got == "dc-pi-core" and "[dc-pi-core]" in said and "Permanent" in said, (got, said))
got, said = ask_dc(["a-name-far-too-long", "ad", "12", "DC-Kitchen"])
check("negative: too long, the domain's NetBIOS name, only digits each refused saying why, then any valid name taken",
      got == "dc-kitchen" and "1-15 letters" in said and "NetBIOS name" in said and "only digits" in said,
      (got, said))
got, said = ask_dc([], {"dc_name": "pi-core"})
check("an install that has its DC's name keeps it, nothing asked", got == "pi-core" and said == "", (got, said))
got, said = ask_dc([], unattended=True)
check("unattended: the suggestion is taken", got == "dc-pi-core", (got, said))
got, said = ask_dc([], {"dc_name": "not valid!"}, unattended=True)
check("negative: unattended, an invalid dc_name in the vars file is refused, saying why",
      got is None and "dc_name" in said and "1-15 letters" in said, said)

print("--- the vars editor: dc_name refused like ad_domain, the host's name warned (2.1.6.45)")
import fabriclib.menu.edit_category as m_edit  # noqa: E402
import fabriclib.menu.run_vars_menu as m_menu  # noqa: E402
from fabriclib.menu.constants import IMMUTABLE_KEYS, WARNED_KEYS  # noqa: E402


def editor(fn, answers, data):
    """Drive one vars-editor screen with these answers; nothing is saved or applied; what it printed."""
    feed, real, saved = iter(answers), builtins.input, []
    builtins.input = lambda prompt="": (print(prompt), next(feed))[1]
    m_edit.os.system = lambda cmd: 0
    m_edit.save_menu_change = m_menu.save_menu_change = lambda path, d, k, old, new, *a: saved.append((k, new))
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            fn(data)
    except (StopIteration, SystemExit):
        pass
    finally:
        builtins.input = real
    return out.getvalue(), saved


data = {"dc_name": "dc-pi-core", "hostname": "pi-core"}
said, saved = editor(lambda d: m_edit.edit_category("Advanced", d, lambda x: list(x)), ["1", "", "2", "kitchen", "",
                                                                                      "b"], data)
check("dc_name is immutable and the host's name warned (not immutable any more)",
      "dc_name" in IMMUTABLE_KEYS and "hostname" not in IMMUTABLE_KEYS and "hostname" in WARNED_KEYS)
check("negative: editing dc_name is refused, unchanged; the host's name changes after a warning",
      "'dc_name' is an immutable variable" in said and data["dc_name"] == "dc-pi-core" and "WARNING" in said
      and saved == [("hostname", "kitchen")], (said[-600:], saved))
m_menu.load_vars = lambda path: dict(data)
said, saved = editor(lambda d: m_menu.run_vars_menu(), ["a", "dc_name", "", "a", "note", "x", "q"], data)
check("negative: adding dc_name over the one set is refused too; adding another key works",
      "Cannot change immutable key: dc_name" in said and saved == [("note", "x")], (said[-600:], saved))

print("--- the memory fabric may use (2.1.2.3, manual 1.2.4.2): all of it unless set, not asked (2.1.2.16)")

import fabriclib.setup.set_ram_capacity as m_ram  # noqa: E402


def ram(have, data):
    """set_ram_capacity with the host's memory faked (pure logic)."""
    m_ram.host_ram_gb = lambda: have
    real = builtins.input
    builtins.input = lambda prompt="": (_ for _ in ()).throw(AssertionError(f"asked: {prompt}"))
    try:
        m_ram.set_ram_capacity(data)
        return data.get("host_ram_capacity")
    except SetupError as e:
        return f"refused: {e}"
    finally:
        builtins.input = real


check("a host under 4 GB is refused", str(ram(3, {})).startswith("refused"))
check("the measured memory is used and kept, nothing asked", ram(8, {}) == 8)
check("a value set by the admin is kept when it fits", ram(8, {"host_ram_capacity": 6}) == 6)
# covers: setting:host_ram_capacity -
check("refused: more than the host has, or under 4", str(ram(8, {"host_ram_capacity": 12})).startswith("refused")
      and str(ram(8, {"host_ram_capacity": 2})).startswith("refused"))

print("--- the Administrator's password")
pw = [random_password() for _ in range(200)]
check("64 characters, letters of both cases and digits in every one (any allowed policy accepts it)",
      all(len(p) == 64 and any(c in string.ascii_uppercase for c in p) and any(c in string.ascii_lowercase for c in p)
          and any(c in string.digits for c in p) and p.isalnum() for p in pw))
check("never the same twice", len(set(pw)) == len(pw))

print("--- the rendered container (manual 1.6.5.3, 1.2.7)")
env = jinja_env(os.path.join(REPO, "templates"))
base = {"domain": "lan.test", "hostname": "pi-core", "host_ip": "192.168.7.53", "lan_cidr": "192.168.7.0/24",
        "lan_gateway": "192.168.7.1", "ad_domain": "AD.lan.test",
        "ad_password_policy": POLICY}
v = yaml.safe_load(env.get_template("vars.yaml.j2").render(**base))
# covers: setting:ad_domain +
check("the domain's names follow from ad_domain (lower-cased; realm, base DN, NetBIOS, the DC's name)",
      (v["ad_domain"], v["ad_realm"], v["ad_base_dn"], v["ad_netbios"], v["hostname_dc"])
      == ("ad.lan.test", "AD.LAN.TEST", "DC=ad,DC=lan,DC=test", "AD", "dc-pi-core.ad.lan.test"),
      (v["ad_domain"], v["ad_realm"], v["ad_base_dn"], v["ad_netbios"], v["hostname_dc"]))
check("the limit is planned (1.2.4.3): 512 MB at least at 4 GB, the smallest host (2.1.2.3); no samba_mem_limit written", v["memory_plan"]["limits"]["samba"] >= 512 and v["samba_mem_limit"] is None, v["memory_plan"])
dc = yaml.safe_load(env.get_template("samba/docker-compose.yml.j2").render(**v))["services"]["samba"]
check("host network (2.1.6.18), read-only, no-new-privileges, every capability dropped",
      dc["network_mode"] == "host" and dc["read_only"] is True and dc["cap_drop"] == ["ALL"]
      and "no-new-privileges:true" in dc["security_opt"])
check("exactly the six capabilities of the inventory (1.2.7)",
      sorted(dc["cap_add"]) == ["CHOWN", "DAC_OVERRIDE", "FOWNER", "NET_BIND_SERVICE", "SETGID", "SETUID"],
      dc["cap_add"])
check("bound to loopback, the host's address and fabric_net's gateway only (containers reach it there, 2.1.2.15)",
      dc["environment"]["INTERFACES"] == "127.0.0.1 192.168.7.53 10.255.0.1", dc["environment"]["INTERFACES"])
check("no secret in its environment (the Administrator's password comes as a file)",
      not any(k.endswith(("PASSWORD", "SECRET", "PASS")) for k in dc["environment"]), sorted(dc["environment"]))
check("its resolver is fabric's file (the host's address), not the host's resolver",
      "/opt/samba/resolv.conf:/etc/resolv.conf:ro" in dc["volumes"])
check("the DC's time-signing socket in the one folder chrony's AppArmor profile allows (2.1.13.1)",
      "/var/lib/samba/ntp_signd:/run/samba/ntp_signd" in dc["volumes"], dc["volumes"])
check("its secrets, certificate and converge code are mounted read-only",
      all(any(m.endswith(f":{target}:ro") for m in dc["volumes"]) for target in ("/run/secrets", "/tls", "/fabric")))
check("a memory limit: the planned one", dc["mem_limit"] == f"{v['memory_plan']['limits']['samba']}m", dc["mem_limit"])
check("fabric's published image, pinned by digest; or, while it is pending, built here with BIND's and FreeRADIUS's gids",
      ("@sha256:" in dc["image"] and "build" not in dc)
      or (dc.get("build", {}).get("args", {}).get("BIND_GID") == "600"
          and dc.get("build", {}).get("args", {}).get("RADIUS_GID") == "610"), dc.get("image"))

big = yaml.safe_load(env.get_template("vars.yaml.j2").render(**base, host_ram_capacity=8, install_keycloak=True))
# the same parts at 4 GB: under the budget a DC without Keycloak beside it takes Keycloak's share too (2.1.1.47)
small = yaml.safe_load(env.get_template("vars.yaml.j2").render(**base, host_ram_capacity=4, install_keycloak=True))
kc8 = yaml.safe_load(env.get_template("keycloak/docker-compose.yml.j2").render(**big))["services"]["keycloak"]
# covers: setting:host_ram_capacity +
check("at 8 GB the growing services take more than at 4 GB: Keycloak and the DC (their planned limits, 1.2.4.3)",
      kc8["deploy"]["resources"]["limits"]["memory"] == f"{big['memory_plan']['limits']['keycloak']}M"
      and big["memory_plan"]["limits"]["keycloak"] > small["memory_plan"]["limits"]["keycloak"] > 1024
      and big["memory_plan"]["limits"]["samba"] > small["memory_plan"]["limits"]["samba"],
      (kc8.get("deploy"), big["memory_plan"]))

print("--- what changes around it")
ngx = env.get_template("nginx/nginx.conf.j2").render(**v)
ports = yaml.safe_load(env.get_template("nginx/docker-compose.yml.j2").render(**v))["services"]["nginx"]["ports"]
check("nginx passes nothing on 389/636 (the DC owns them)",
      "listen 389" not in ngx and "listen 636" not in ngx and not any(":389:" in p or ":636:" in p for p in ports), ports)
named = env.get_template("bind9/config/named.conf.j2").render(**v)
opts = env.get_template("bind9/config/named.conf.options.j2").render(**v)
check("BIND includes the AD zone (DLZ) and the keytab option (manual 1.6.5.6)",
      'include "/etc/bind-samba/dlz.conf";' in named and 'include "/etc/bind-samba/options.conf";' in opts)
b = yaml.safe_load(env.get_template("bind9/docker-compose.yml.j2").render(**{**v, "host_ram_capacity": 4}))
b = b["services"]["bind9"]
check("BIND mounts fabric's DLZ files and the DC's smb.conf read-only, the DNS partition writable",
      "/opt/samba/bind:/etc/bind-samba:ro" in b["volumes"] and "/opt/samba/data/etc:/etc/samba:ro" in b["volumes"]
      and "/opt/samba/data/bind-dns:/data/bind-dns" in b["volumes"], b["volumes"])
check("BIND gets a Kerberos replay cache and 128 MiB at least at 4 GB (Samba's DLZ libraries)",
      any(t.startswith("/var/tmp:") for t in b["tmpfs"])
      and int(b["deploy"]["resources"]["limits"]["memory"].rstrip("M")) >= 128, b.get("deploy"))
sibling = {**v, "ad_domain": "ad.test"}
check("the DNS filter forwards the AD zone to BIND, also when it sits beside fabric's domain (ad.<parent>)",
      "ad.test" in adguard_zones(sibling, {}) and "ad.lan.test" in adguard_zones(v, {}))
units = {u["service"]: u for u in service_units("/opt", v)}
check("a samba unit on every install, requiring nothing",
      units["samba"]["enabled"] and units["samba"]["requires"] == [])

print("--- who may sign in, per OU (manual 1.6.11.4): the setting, checked at apply; a fresh install's default")
import tempfile  # noqa: E402

from fabriclib.deploy.check_settings import check_settings  # noqa: E402
from fabriclib.samba.check_logon_policies import check_logon_policies  # noqa: E402
import fabriclib.setup.collect_vars as m_collect  # noqa: E402
from fabriclib.setup.collect_vars import collect_vars  # noqa: E402

m_collect.network_problem = lambda data: ""         # the test's addresses are not this machine's (pure logic)


def logon_refused(value, words):
    try:
        check_logon_policies(value)
    except ValidationError as e:
        return words in str(e) or print(f"    refused, but: {e}")
    return False


check("logon_policies renders null by default (an upgrade keeps the rights it has, 2.1.6.44)",
      "logon_policies" in v and v["logon_policies"] is None, v.get("logon_policies"))
odd = "lan-x: #1 'q' $(id)"
lp = yaml.safe_load(env.get_template("vars.yaml.j2").render(
    **base, logon_policies={"machines": {"console": ["lan-machine-admins"], "remote": [odd]}}))
check("logon_policies renders as it was set, a value with YAML's and the shell's specials read back as itself (1.1.5.7)",
      lp["logon_policies"] == {"machines": {"console": ["lan-machine-admins"], "remote": [odd]}}, lp["logon_policies"])
# covers: setting:logon_policies +
check("accepted and normalised: OU paths in lower case (Site and / for the site's OU), groups stripped, a repeat "
      "dropped, a right left out empty, Domain Admins with its space",
      check_logon_policies({"Machines/Linux/": {"console": [" lan-devs", "LAN-devs"]},
                            "site": {"console": ["Domain Admins"], "remote": ["Domain Admins"]}})
      == {"": {"console": ["Domain Admins"], "remote": ["Domain Admins"]},
          "machines/linux": {"console": ["lan-devs"], "remote": []}})
check("accepted: null (the site's rights as before 0.9); an OU below machines granting nobody (a locked-down OU)",
      check_logon_policies(None) is None and check_logon_policies(
          {"machines": {"console": ["a"]}, "machines/vault": {"console": [], "remote": []}})["machines/vault"]
      == {"console": [], "remote": []})
# covers: setting:logon_policies -
check("refused: a map without the site's OU or OU=machines (the site's machines would have no policy of fabric's)",
      logon_refused({}, "no policy on the site's OU") and logon_refused({"machines/linux": {"console": ["a"]}},
                                                                           "no policy on the site's OU"))
check("refused: OU=machines or the site's OU granting nobody (only break-glass could sign in)",
      logon_refused({"machines": {"console": [], "remote": []}}, "grants nobody")
      and logon_refused({"": {}, "machines": {"console": ["a"]}}, "grants nobody"))
check("refused: an OU path with a space, a comma or an empty part, nine levels, or `rights` (the legacy GPO's name)",
      logon_refused({"machines/a b": {"console": ["a"]}, "machines": {"console": ["a"]}}, "a path below")
      and logon_refused({"OU=x,DC=y": {"console": ["a"]}, "machines": {"console": ["a"]}}, "a path below")
      and logon_refused({"machines//x": {"console": ["a"]}, "machines": {"console": ["a"]}}, "a path below")
      and logon_refused({"/".join("abcdefghi"): {"console": ["a"]}, "machines": {"console": ["a"]}}, "a path below")
      and logon_refused({"rights": {"console": ["a"]}, "machines": {"console": ["a"]}}, "rights"))
check("refused: a group name AD could not hold (a comma, brackets, a leading space kept by a list item that is not "
      "text), a right that is not a list, an unknown key, the same OU twice, a value that is not a map",
      logon_refused({"machines": {"console": ["a,b"]}}, "not a group name")
      and logon_refused({"machines": {"console": ["[x]"]}}, "not a group name")
      and logon_refused({"machines": {"console": [5]}}, "not a group name")
      and logon_refused({"machines": {"console": "a"}}, "a list of group names")
      and logon_refused({"machines": {"console": ["a"], "ssh": ["a"]}}, "only console and remote")
      and logon_refused({"machines": {"console": ["a"]}, "Machines": {"console": ["a"]}}, "named twice")
      and logon_refused(["machines"], "a map of OU path"))
try:
    check_settings({**v, "dns_filter": "none", "logon_policies": {"machines": {"console": []}}})
    applied = "accepted"
except ValidationError as e:
    applied = str(e)
check("refused at apply: check_settings checks logon_policies before anything is rendered",
      "grants nobody" in applied, applied)
# pki_manual_max_days (2.3.1.15): a cap that is not a whole number of days is refused at apply, not on the PKI page
for bad in ("abc", "0", "-5", "12.5"):
    try:
        check_settings({**v, "dns_filter": "none", "pki_manual_max_days": bad})
        said = "accepted"
    except ValidationError as e:
        said = str(e)
    # covers: setting:pki_manual_max_days -
    check(f"refused at apply: pki_manual_max_days {bad!r}, saying it must be a whole number of days",
          "pki_manual_max_days must be a whole number of days" in said, said)
_ok = {**v, "dns_filter": "none", "pki_manual_max_days": "90"}
check_settings(_ok)
check("...and a whole number is accepted, as a number", _ok["pki_manual_max_days"] == 90, _ok["pki_manual_max_days"])

tmp = tempfile.mkdtemp()
answers = os.path.join(tmp, "answers.yaml")
with open(answers, "w") as f:
    yaml.safe_dump({**{k: base[k] for k in ("domain", "hostname", "host_ip", "lan_cidr", "lan_gateway")},
                    "ad_domain": "ad.lan.test", "site_name": "Lan", "host_ram_capacity": 8}, f)


def setup_vars(vars_file, provisioned=False):
    """collect_vars as setup runs it unattended with a vars file (pure logic: files in a scratch folder)."""
    base_dir = tempfile.mkdtemp(dir=tmp)
    if provisioned:
        os.makedirs(os.path.join(base_dir, "samba", "data"))
        open(os.path.join(base_dir, "samba", "data", ".fabric-provisioned"), "w").close()
    ctx = types.SimpleNamespace(user_vars_file=answers, vars_file=vars_file, source_dir=os.path.join(tmp, "src"),
                                config_dir=os.path.join(base_dir, "config"), deploy_base=base_dir,
                                join_invitation=None, non_interactive=True, origins={},
                                secrets_file=os.path.join(base_dir, "secrets.yml"))
    with contextlib.redirect_stdout(io.StringIO()):
        collect_vars(ctx)
    return ctx.vars


fresh = setup_vars(os.path.join(tmp, "none.yaml"))
check("a fresh install: the site's machine admins may sign in to its OU=machines, at the keyboard and remotely "
      "(2.1.6.42)", fresh.get("logon_policies") == {"machines": {"console": ["lan-machine-admins"],
                                                                 "remote": ["lan-machine-admins"]}},
      fresh.get("logon_policies"))
existing = os.path.join(tmp, "vars.yaml")
with open(existing, "w") as f:
    yaml.safe_dump({"ad_password_policy": POLICY}, f)
check("an upgrade (a vars file already there) keeps the log-on rights it has: no logon_policies (2.1.6.44)",
      "logon_policies" not in setup_vars(existing), "set on an upgrade")
check("a reinstall over a provisioned domain keeps them too (no vars file, but the domain's marker)",
      "logon_policies" not in setup_vars(os.path.join(tmp, "none.yaml"), provisioned=True), "set on a reinstall")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
