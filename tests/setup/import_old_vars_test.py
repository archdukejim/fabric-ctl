"""Setup takes a 0.7.x settings file as it is (decision 2.1.1.60, manual 3.3.5.3): `fabricctl setup --file` with a
0.7.1 install's vars.yaml (tests/setup/vars-0.7.1.yaml, made by 0.7.1's own code) lists the keys 0.8.0 no longer
takes and ignores them, keeps the zones, records, TSIG keys' rights and parts, and renders as a fresh 0.8.0 install
with the same answers would; what 0.8.0 adds is asked, or refused unattended naming every key to add; a damaged or
non-fabric file is refused with nothing written. Pure: collect_vars in a scratch folder.
    python3 tests/setup/import_old_vars_test.py"""
import contextlib
import io
import os
import sys
import tempfile
import types

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.setup.ask_first_admin as m_admin  # noqa: E402
import fabriclib.setup.collect_vars as m_collect  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.deploy.check_settings import check_settings  # noqa: E402
from fabriclib.deploy.render_vars import render_vars  # noqa: E402
from fabriclib.setup.collect_vars import collect_vars  # noqa: E402
from fabriclib.setup.common.retired_settings import OLD_FILE_MARKS, RETIRED_SETTINGS  # noqa: E402
from fabriclib.setup.drop_retired_settings import drop_retired_settings  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402

PASS = FAIL = 0
OLD = os.path.join(HERE, "vars-0.7.1.yaml")
old = yaml.safe_load(open(OLD))
m_collect.network_problem = lambda data: ""        # the file's addresses are the sandbox's, not this machine's
tmp = tempfile.mkdtemp()


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


def setup_vars(user_file, interactive=False):
    """collect_vars as `fabricctl setup --file` runs it on a fresh host; returns (ctx, output, error)."""
    base = tempfile.mkdtemp(dir=tmp)
    ctx = types.SimpleNamespace(user_vars_file=user_file, vars_file=os.path.join(base, "fabric", "config", "vars.yaml"),
                                source_dir=os.path.join(base, "src"), config_dir=os.path.join(base, "fabric", "config"),
                                deploy_base=base, join_invitation=None, non_interactive=not interactive, origins={},
                                secrets_file=os.path.join(base, "fabric", "config", "fabric-secrets.yml"),
                                admin_password=None, admin_password_file=None, vars={})
    out, error = io.StringIO(), None
    with contextlib.redirect_stdout(out):
        try:
            collect_vars(ctx)
        except SetupError as e:
            error = str(e)
    return ctx, out.getvalue(), error


def write(name, text):
    path = os.path.join(tmp, name)
    with open(path, "w") as f:
        f.write(text)
    return path


print("--- the table: what a 0.7.x file holds that 0.8.0 no longer takes")
kept, ignored = drop_retired_settings(old)
names = [k for k, _ in ignored]
check("every retired key a 0.7.1 vars.yaml holds is ignored, each with why",
      set(names) == {k for k in RETIRED_SETTINGS if k in old} | {"ldap_groups"} and all(w for _, w in ignored), ignored)
check("...dc_name, the id settings, the log-on policies, the site OUs and the admins' group among them",
      {"dc_name", "posix_id_start", "posix_id_block", "posix_id_range", "logon_policies", "ad_site_ou", "ad_org_ou",
       "webui_admin_group"} <= set(names), names)
check("...and 0.7.x's own groups (admins, ...) leave ldap_groups; nothing else is taken out",
      "ldap_groups" not in kept and set(old) - set(kept) == set(names), sorted(set(old) - set(kept)))
mine = {"name": "lab-people", "gidNumber": 1040100}
kept2, _ = drop_retired_settings({**old, "ldap_groups": old["ldap_groups"] + [mine]})
check("a group the admin added to a 0.7.x file is kept", kept2.get("ldap_groups") == [mine], kept2.get("ldap_groups"))
newer = {"domain": "x.home.arpa", "dc_name": "dc-office", "image_pins": ["image_fabric_samba"]}
check("a newer file keeps dc_name (refused as before, 2.1.6.65) and image_pins: only a 0.7.x file's are ignored",
      drop_retired_settings(newer) == (newer, []) and set(OLD_FILE_MARKS) <= set(old), drop_retired_settings(newer))

print("--- setup --file with the 0.7.1 file, unattended")
answers = {"webui_admin_user": "jdoe", "webui_admin_first_name": "Jane", "webui_admin_last_name": "Doe"}
moved_file = write("vars-0.7-plus.yaml", open(OLD).read() + yaml.safe_dump(answers))
ctx, out, error = setup_vars(OLD)
# covers: cli:setup +
check("the 0.7.1 file is taken as it is: the ignored keys listed with why, nothing refused",
      error is None and "setting(s) this release no longer takes, ignored (3.3.5.3)" in out
      and all(f"  {k}: " in out for k in names), error or out)
audit = os.path.join(ctx.deploy_base, "fabric", "archive", "audit.log")
check("...and the list is logged (the audit log, SETUP_IMPORT)",
      os.path.exists(audit) and "SETUP_IMPORT" in open(audit).read() and "posix_id_start" in open(audit).read())
saved = yaml.safe_load(open(os.path.join(ctx.config_dir, "fabric.yaml")))
check("fabric.yaml holds no retired key; the DC is fabric's dc-0001, not 0.7.x's dc-<host>",
      not set(saved) & (set(RETIRED_SETTINGS) - {"dc_name"}) and saved.get("dc_name") == "dc-0001",
      {k: saved.get(k) for k in RETIRED_SETTINGS if k in saved})
check("kept: the zones and their records", saved.get("dns") == old["dns"], saved.get("dns"))
check("kept: the TSIG keys' names and rights (no secret in the file)",
      saved.get("tsig_keys") == old["tsig_keys"] and not any("secret" in k for k in saved["tsig_keys"]),
      saved.get("tsig_keys"))
parts = ("install_keycloak", "install_webui", "install_fluentbit", "install_kea", "install_freeradius", "dns_filter",
         "log_forwarding", "host_ram_capacity", "ad_password_policy", "bind_acls", "bind_acl_policies")
check("kept: the parts chosen and their settings", all(saved.get(k) == old.get(k) for k in parts),
      {k: (old.get(k), saved.get(k)) for k in parts if saved.get(k) != old.get(k)})

secrets = dict(ca_password="x", rndc_secret="eA==", keycloak_admin_user="admin", keycloak_admin_password="x",
               keycloak_db_password="x", webui_oidc_secret="x", tsig_secrets={"acme": "eA==", "ddns": "eA=="})
env = jinja_env(os.path.join(REPO, "templates"))
fresh_answers = {k: old[k] for k in ("deploy_base_dir", "domain", "hostname", "host_ip", "lan_cidr", "lan_gateway",
                                     "friendly_name", "ad_domain", "tsig_keys", "dns") + parts}
fresh_answers.update(answers, webui_admin_email=old["webui_admin_email"])
ctx_fresh, _, error = setup_vars(write("fresh.yaml", yaml.safe_dump(fresh_answers)))
fresh_saved = yaml.safe_load(open(os.path.join(ctx_fresh.config_dir, "fabric.yaml")))
fresh, _ = render_vars(env, secrets, {**fresh_saved, "deploy_base_dir": "/opt"})
moved, _ = render_vars(env, secrets, {**saved, **answers, "deploy_base_dir": "/opt"})
# covers: setting:cname_mgr +
check("the console's address: a new install's is fabric-ctl.<domain>; the 0.7.1 install keeps its fabric.<domain> "
      "(its cname_mgr kept, 2.1.8.12, 1.2.13.4)", fresh["hostname_mgr"] == f"fabric-ctl.{old['domain']}"
      and moved["cname_mgr"] == "fabric" and moved["hostname_mgr"] == f"fabric.{old['domain']}",
      (fresh["hostname_mgr"], moved["hostname_mgr"]))
ctx_same, _, error = setup_vars(write("same.yaml", yaml.safe_dump({**fresh_answers, "cname_mgr": old["cname_mgr"]})))
same, _ = render_vars(env, secrets, {**yaml.safe_load(open(os.path.join(ctx_same.config_dir, "fabric.yaml"))),
                                     "deploy_base_dir": "/opt"})
# install_was_ready (2.1.4.10): the moved file names hostname_landing, so it counts as an install once ready (its
# zone, info included, is the admin's); a fresh one is not ready until its first setup ends
differ = sorted(k for k in set(same) | set(moved) if same.get(k) != moved.get(k) and k != "install_was_ready")
check("0.8.0 renders the moved settings as a fresh install with the same answers (zones, keys, parts, groups, "
      "the DC; the console's kept address aside)", differ == [] and moved["install_was_ready"] is True
      and same["install_was_ready"] is False, {k: (same.get(k), moved.get(k)) for k in differ})
try:
    check_settings({**moved, "dns_filter": "none"})
    said = "accepted"
except Exception as e:                      # noqa: BLE001  (any refusal is the finding)
    said = f"{type(e).__name__}: {e}"
check("...and they pass 0.8.0's settings check", said == "accepted", said)

print("--- what 0.8.0 adds: the first Directory Administrator (2.1.6.69, 2.1.6.93)")
ctx.vars.update(install_webui=True, install_keycloak=True)
m_admin.first_admin_needed = lambda ctx: True
try:
    m_admin.ask_first_admin(ctx)
    said = "accepted"
except SetupError as e:
    said = str(e)
# covers: cli:setup -
check("unattended: refused, naming every key to add at once (0.7.1's admin name fabric-admin is the Enterprise "
      "Admin's; the first and last names are new)",
      "webui_admin_user in the vars file" in said and "webui_admin_first_name in the vars file" in said
      and "webui_admin_last_name in the vars file" in said and "webui_admin_email" not in said, said)
asked = []
m_admin.ask_admin_fact = lambda key, cur: asked.append(key) or answers[key]
ctx2, _, error = setup_vars(OLD, interactive=True)
ctx2.non_interactive, ctx2.admin_password = False, "set"      # the password is asked after the facts
ctx2.vars.update(install_webui=True, install_keycloak=True)
m_admin.ask_first_admin(ctx2)
check("interactive: those keys are asked, and only those; the e-mail address of the file is kept",
      error is None and asked == ["webui_admin_user", "webui_admin_first_name", "webui_admin_last_name"]
      and ctx2.vars["webui_admin_email"] == old["webui_admin_email"], (error, asked))
asked.clear()
ctx4, _, error = setup_vars(OLD, interactive=True)
ctx4.non_interactive, ctx4.admin_password = False, "set"
ctx4.vars.update(install_webui=True, install_keycloak=True, webui_admin_email="")
m_admin.ask_admin_fact = lambda key, cur: asked.append(key) or {**answers, "webui_admin_email": ""}[key]
m_admin.ask_first_admin(ctx4)
check("interactive, the file giving no e-mail address: it is asked too (optional: Enter leaves it empty, 2.1.6.93)",
      error is None and asked == ["webui_admin_user", "webui_admin_first_name", "webui_admin_last_name",
                                  "webui_admin_email"] and ctx4.vars["webui_admin_email"] == "", (error, asked))
ctx3, _, error = setup_vars(moved_file)
ctx3.admin_password = "set"
ctx3.vars.update(install_webui=True, install_keycloak=True)
try:
    m_admin.ask_first_admin(ctx3)
    said = "accepted"
except SetupError as e:
    said = str(e)
# covers: cli:setup +
check("unattended with those keys added to the 0.7.1 file: accepted",
      error is None and said == "accepted" and ctx3.vars["webui_admin_user"] == "jdoe", (error, said))

print("--- a damaged or non-fabric file is refused, nothing written")
for name, text, want in (
        ("damaged.yaml", open(OLD).read()[:300] + "\n  - : [unclosed\n", "is damaged: it is not YAML"),
        ("list.yaml", "- domain: x.home.arpa\n", "holds no settings"),
        ("empty.yaml", "", "holds no settings"),
        ("export.yaml", "fabric_settings: 1\nsettings: {dns_filter: bind}\n", "fabricctl settings import"),
        ("compose.yaml", "services:\n  web: {image: nginx}\nvolumes: {}\n", "is not a fabric vars file")):
    c, _, error = setup_vars(write(name, text))
    # covers: cli:setup -
    check(f"refused: {name} ({want}), saying nothing was changed; no fabric.yaml written",
          error is not None and want in error and "nothing was changed" in error
          and not os.path.exists(os.path.join(c.config_dir, "fabric.yaml")), error)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
