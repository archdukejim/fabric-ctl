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
from fabriclib.samba.read_policy_changes import read_policy_changes  # noqa: E402
from fabriclib.samba.suggested_ad_domain import suggested_ad_domain  # noqa: E402
from fabriclib.samba.summarize_roles import summarize_roles  # noqa: E402
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

print("--- the console's Domain section (2.1.2.22): the roles named plainly, the policy typed as the command types it")
_DN = "CN=NTDS Settings,CN={},CN=Servers,CN=lan,CN=Sites,CN=Configuration,DC=ad,DC=lan,DC=test"
_ROLES = ["SchemaMaster", "InfrastructureMaster", "RidAllocationMaster", "PdcEmulationMaster", "DomainNamingMaster",
          "DomainDnsZonesMaster", "ForestDnsZonesMaster"]
s = summarize_roles([f"{r}Role owner: {_DN.format('DC-PI-CORE')}" for r in _ROLES], "dc-pi-core.ad.lan.test")
check("roles: all held here -> 'This controller holds all five roles', no DN shown",
      s["text"].startswith("This controller holds all five roles") and "CN=" not in s["text"] and not s["elsewhere"],
      s)
s = summarize_roles([f"{r}Role owner: {_DN.format('DC-LAB' if r == 'PdcEmulationMaster' else 'DC-PI-CORE')}"
                     for r in _ROLES], "dc-pi-core.ad.lan.test")
check("roles: one held by another controller -> named with it, the rest held here",
      "DC-LAB holds the PDC emulator" in s["text"] and "schema master" in s["text"] and "CN=" not in s["text"], s)
check("roles: none read (the DC not running) -> no sentence", summarize_roles([], "dc-pi-core")["text"] == "")
check("policy form: digits and on/off typed as the command's options",
      read_policy_changes({"minimum_length": "14", "complexity": "off", "lockout_minutes": 30, "actor": "x"})
      == {"minimum_length": 14, "complexity": False, "lockout_minutes": 30})
for data, words in (({"minimum_length": "twelve"}, "whole number"), ({"history": "-1"}, "whole number"),
                    ({"complexity": "yes"}, "on or off"), ({"colour": "1"}, "unknown policy setting"), ({}, "no policy"),
                    ({"history": True}, "whole number")):
    try:
        read_policy_changes(data)
        ok = False
    except ValidationError as e:
        ok = words in str(e)
    check(f"policy form refused: {data} ({words})", ok)

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

print("--- the DC's name, fabric's alone (2.1.6.65, manual 1.6.5.26): never asked, dc-0001 for a new domain")
import tempfile as _tf  # noqa: E402

from fabriclib.setup.errors import SetupError  # noqa: E402
from fabriclib.setup.name_dc import name_dc  # noqa: E402


def name_of(have=None, unattended=False, installed=False, joining=None, upstream=None):
    """setup's naming of the DC, with input() refusing to be called; the settings' dc_name after it (or the refusal)."""
    base = _tf.mkdtemp()
    os.makedirs(os.path.join(base, "fabric", "config"))
    if installed:
        os.makedirs(os.path.join(base, "samba", "data"))
        open(os.path.join(base, "samba", "data", ".fabric-provisioned"), "w").close()
    if upstream:
        with open(os.path.join(base, "fabric", "config", "federation.yaml"), "w") as f:
            yaml.safe_dump({"upstream": upstream}, f)
    ctx = types.SimpleNamespace(vars={"hostname": "Pi-Core", "ad_domain": "ad.lan.test", **(have or {})},
                                non_interactive=unattended, deploy_base=base,
                                config_dir=os.path.join(base, "fabric", "config"), join_invitation=joining)
    real, asked = builtins.input, []
    builtins.input = lambda prompt="": asked.append(prompt) or ""
    try:
        name_dc(ctx)
    except SetupError as e:
        return None, str(e)
    finally:
        builtins.input = real
    return ctx.vars.get("dc_name", "(unset)"), asked


# covers: setting:dc_name +
check("a new domain's DC is dc-0001, nothing asked: interactive and unattended",
      name_of() == ("dc-0001", []) and name_of(unattended=True) == ("dc-0001", []), (name_of(), name_of(unattended=True)))
check("a name left in the settings of a host whose DC is not installed is fabric's to replace: dc-0001",
      name_of({"dc_name": "dc-kitchen"}) == ("dc-0001", []), name_of({"dc_name": "dc-kitchen"}))
check("a host named dc-0001: its DC takes dc-0002 (the host joins the domain under its own name, 2.1.6.51)",
      name_of({"hostname": "dc-0001"})[0] == "dc-0002", name_of({"hostname": "dc-0001"}))
check("an installed DC keeps the name it has, 0.7.x's dc-<host> included; nothing asked",
      name_of({"dc_name": "dc-pi-core"}, installed=True) == ("dc-pi-core", [])
      and name_of({"dc_name": "dc-pi-core"}, unattended=True, installed=True) == ("dc-pi-core", []),
      name_of({"dc_name": "dc-pi-core"}, installed=True))
check("a site joining now has no name until the upstream gives one (a name left over is dropped)",
      name_of({"dc_name": "dc-0001"}, joining="fabric-join-1.x") == ("(unset)", []))
check("a site that joined keeps the name its upstream gave it (a re-run of setup, with or without --join)",
      name_of(upstream={"site_name": "hq", "dc_name": "dc-0002"}) == ("dc-0002", [])
      and name_of(joining="fabric-join-1.x", upstream={"site_name": "hq", "dc_name": "dc-0003"}) == ("dc-0003", []))

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
      == ("ad.lan.test", "AD.LAN.TEST", "DC=ad,DC=lan,DC=test", "AD", "dc-0001.ad.lan.test"),
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

print("--- the per-OU log-on policies are retired (D1, 2.3.6.17): no setting; checked at apply")
import tempfile  # noqa: E402

from fabriclib.deploy.check_settings import check_settings  # noqa: E402
import fabriclib.setup.collect_vars as m_collect  # noqa: E402
from fabriclib.setup.collect_vars import collect_vars  # noqa: E402

m_collect.network_problem = lambda data: ""         # the test's addresses are not this machine's (pure logic)

check("logon_policies is no longer rendered: who signs in is the grants' (D3)", "logon_policies" not in v,
      v.get("logon_policies"))
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


def setup_vars(vars_file, provisioned=False, user_file=None, base_dir=None):
    """collect_vars as setup runs it unattended with a vars file (pure logic: files in a scratch folder)."""
    base_dir = base_dir or tempfile.mkdtemp(dir=tmp)
    if provisioned:
        os.makedirs(os.path.join(base_dir, "samba", "data"))
        open(os.path.join(base_dir, "samba", "data", ".fabric-provisioned"), "w").close()
    ctx = types.SimpleNamespace(user_vars_file=user_file or answers, vars_file=vars_file, source_dir=os.path.join(tmp, "src"),
                                config_dir=os.path.join(base_dir, "config"), deploy_base=base_dir,
                                join_invitation=None, non_interactive=True, origins={},
                                secrets_file=os.path.join(base_dir, "secrets.yml"))
    with contextlib.redirect_stdout(io.StringIO()):
        collect_vars(ctx)
    return ctx.vars


fresh = setup_vars(os.path.join(tmp, "none.yaml"))
check("a fresh install sets no log-on policy (retired in D1: sign-in on joined machines is open until D3's grants)",
      "logon_policies" not in fresh, fresh.get("logon_policies"))
print("--- a settings file naming the DC (2.1.6.65): refused for a new install, an installed DC's name kept")
# covers: cli:setup +
check("a new install, unattended with a vars file: the DC is dc-0001, nothing asked", fresh.get("dc_name") == "dc-0001",
      fresh.get("dc_name"))
named = os.path.join(tmp, "named.yaml")
with open(named, "w") as f:
    yaml.safe_dump({**yaml.safe_load(open(answers)), "dc_name": "dc-office"}, f)
new_base = tempfile.mkdtemp(dir=tmp)
try:
    setup_vars(os.path.join(tmp, "none.yaml"), user_file=named, base_dir=new_base)
    said = "accepted"
except SetupError as e:
    said = str(e)
# covers: cli:setup setting:dc_name -
check("negative: a new install's --file that names the DC is refused, saying fabric names DCs itself; nothing written",
      "names the domain controller (dc_name)" in said and "fabric names its domain controllers itself" in said
      and "dc-office" not in said and "dc-0001" not in said
      and "nothing was changed" in said and not os.path.exists(os.path.join(new_base, "config", "fabric.yaml")), said)
legacy = os.path.join(tmp, "legacy.yaml")
with open(legacy, "w") as f:
    yaml.safe_dump({"ad_password_policy": POLICY, "dc_name": "dc-pi-core", "hostname": "pi-core"}, f)
check("an installed host's upgrade keeps its DC's legacy name, 0.7.x's dc-<host> (nothing renamed)",
      setup_vars(legacy, provisioned=True).get("dc_name") == "dc-pi-core", "renamed on an upgrade")
check("…and a --file naming another DC there is not taken: the installed DC keeps its name",
      setup_vars(legacy, provisioned=True, user_file=named).get("dc_name") == "dc-pi-core", "renamed by a --file")
check("…and check_samba_settings accepts that legacy name for the installed DC",
      not refused({**GOOD, "dc_name": "dc-pi-core"}, ""))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
