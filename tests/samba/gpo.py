"""The `samba` suite, the ADMX editor (manual 1.6.5.20, S5.4): `fabricctl gpo` against a real DC with a real template
(Samba's own samba.admx, shipped in the DC's image) and fabric's starter template. Proves: templates loaded into the
central store; policies listed with their elements; text, boolean and list policies written into the site's admin
settings GPO as Windows' editor writes them (read back from SYSVOL), replaced, disabled and cleared; the GPO linked to
the site's OU with its version bumped; refusals (an unknown policy or element, a wrong value, a file that is not a
template).
    sudo python3 tests/samba/gpo.py
"""
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__))]
from start_dc import start_dc  # noqa: E402
import fabriclib.samba.run_gpo_command as m_cmd  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.samba.gpo_request import gpo_request  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-gpo")
NET, SUBNET, IP, DC = "gpo_net", "10.254.34.0/24", "10.254.34.10", "gpodc"
TEXT_POL, TEXT_EL = "POL_33AAE399_07A8_5CC8_882A_393E4B96B259", "TXT_F940E18B_16AE_594B_9669_96417E695AC9"
BOOL_POL, BOOL_EL = "POL_3CD2A970_826E_518E_B5F0_5E6725FF354D", "CHK_5C837672_BFBB_592A_907C_E378BEEDA2E4"
LIST_POL, LIST_EL = "POL_DB5DF501_6F87_42D4_9FEC_E7F32C498BD3", "LST_4F4BA073_4F7B_4B64_A61D_8E75257A4B9F"
SMB = "Software\\Policies\\Samba\\smb_conf"
FAILED = 0
AUDIT = []
m_cmd.write_audit = lambda actor, event, detail, source: AUDIT.append(event)
import fabriclib.samba.set_gpo_policy as m_set  # noqa: E402
import fabriclib.samba.clear_gpo_policy as m_clear  # noqa: E402
m_set.write_audit = m_clear.write_audit = m_cmd.write_audit


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-600:]}"))


def gpo(*args):
    """fabricctl gpo as an admin runs it: (exit status, what it printed)."""
    import contextlib
    import io
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = m_cmd.run_gpo_command(V, list(args), DC)
    return code, out.getvalue()


def refused(req, match):
    try:
        gpo_request(req, DC)
    except ValidationError as e:
        return match.lower() in str(e).lower() or print(f"    refused, but: {e}")
    return False


dc = start_dc(os.path.join(W, "dc"), DC, NET, SUBNET, IP)
V = dc["v"]
admx = os.path.join(W, "admx")
os.makedirs(admx, exist_ok=True)
subprocess.run(["docker", "cp", f"{DC}:/usr/share/samba/admx/.", admx], check=True)
for extra in ("GNOME_Settings.admx", "ru-RU"):              # Samba's own template only
    path = os.path.join(admx, extra)
    subprocess.run(["rm", "-rf", path], check=True)
subprocess.run(["rm", "-f", os.path.join(admx, "en-US", "GNOME_Settings.adml")], check=True)

code, out = gpo("load", admx)
# covers: cli:gpo.load +
check("Samba's own template loads into the central store", code == 0 and "samba.admx" in out, out)
starter = os.path.join(W, "starter")
code, out = gpo("starter", starter)
# covers: cli:gpo.starter +
check("fabric's starter template is copied out for editing",
      code == 0 and os.path.exists(os.path.join(starter, "fabric-starter.admx"))
      and os.path.exists(os.path.join(starter, "en-US", "fabric-starter.adml")), out)
code, out = gpo("load", starter)
check("...and loads as it is", code == 0 and "fabric-starter.admx" in out, out)
check("both are in the central store", gpo_request({"op": "templates"}, DC) == ["fabric-starter", "samba"])
listed = gpo_request({"op": "policies", "match": "additional dns"}, DC)
check("policies are listed by their titles, with their elements",
      [p["name"] for p in listed] == [TEXT_POL] and listed[0]["elements"] == [f"text:{TEXT_EL}"], listed)


def machine():
    return gpo_request({"op": "show", "site": "lan"}, DC)["machine"]


code, out = gpo("set", TEXT_POL, f"{TEXT_EL}=dc-alias.example.org")
# covers: cli:gpo.set +
check("a text policy is set in lan's admin settings GPO", code == 0 and "admin settings" in out
      and [SMB + "\\additional dns hostnames", "additional dns hostnames", 1, "dc-alias.example.org"] in machine(),
      (out, machine()))
gpo("set", BOOL_POL, f"{BOOL_EL}=on")
gpo("set", LIST_POL, f"{LIST_EL}=%lan-admins;%admins")
m = machine()
sudo = "Software\\Policies\\Samba\\Unix Settings\\Sudo Rights"
check("a boolean writes 1, a list replaces all its values (**delvals.) then 1, 2, …",
      [SMB + "\\bind interfaces only", "bind interfaces only", 4, 1] in m
      and [sudo, "**delvals.", 1, " "] in m and [sudo, "1", 1, "%lan-admins"] in m and [sudo, "2", 1, "%admins"] in m, m)
gpo("set", TEXT_POL, f"{TEXT_EL}=other.example.org")
values = [e for e in machine() if e[1] == "additional dns hostnames"]
check("setting a policy again replaces its value (one value, the new one)",
      [e[3] for e in values] == ["other.example.org"], values)
code, out = gpo("set", TEXT_POL, "--disabled")
check("a disabled policy deletes its value (**del.)",
      code == 0 and [SMB + "\\additional dns hostnames", "**del.additional dns hostnames", 1, " "] in machine()
      and not [e for e in machine() if e[1] == "additional dns hostnames"], machine())
code, out = gpo("clear", TEXT_POL)
# covers: cli:gpo.clear +
check("clearing a policy leaves nothing of it, the others untouched",
      code == 0 and not [e for e in machine() if "additional dns" in e[1]] and len(machine()) == 4, machine())
code, out = gpo("set", "ExampleSetting", "ExampleText=hello")
check("the starter template's policy works by name", code == 0
      and ["Software\\Policies\\Example\\Starter", "ExampleText", 1, "hello"] in machine(), out)
code, out = gpo("set", "ExampleSetting", "ExampleText=hello")
check("setting the same value again changes nothing", code == 0 and "already so" in out, out)

READ = r"""
import json, os, sys
import ldb
from samba.dcerpc import preg
from samba.ndr import ndr_unpack
sys.path.insert(0, "/fabric")
from open_samdb import open_samdb
samdb, lp = open_samdb("/data/etc/smb.conf")
g = samdb.search(base="CN=Policies,CN=System," + str(samdb.domain_dn()), scope=ldb.SCOPE_ONELEVEL,
                 expression="(displayName=fabric: lan admin settings)",
                 attrs=["cn", "versionNumber", "gPCMachineExtensionNames"])[0]
folder = os.path.join(lp.get("path", "sysvol"), lp.get("realm").lower(), "Policies", str(g["cn"]))
link = samdb.search(base="OU=lan,OU=sites," + str(samdb.domain_dn()), scope=ldb.SCOPE_BASE, attrs=["gPLink"])[0]
pol = ndr_unpack(preg.file, open(os.path.join(folder, "Machine", "Registry.pol"), "rb").read())
print(json.dumps({"linked": str(g.dn).lower() in str(link["gPLink"][0]).lower(), "version": int(str(g["versionNumber"])),
                  "ext": str(g["gPCMachineExtensionNames"]), "gpt": open(os.path.join(folder, "GPT.INI")).read(),
                  "entries": len(pol.entries)}))
"""
res = subprocess.run(["docker", "exec", "-i", DC, "python3", "-"], input=READ, capture_output=True, text=True)
g = json.loads(res.stdout or "{}") if res.returncode == 0 else {}
check("the GPO is linked to OU=lan, its version bumped in AD and GPT.INI, Registry.pol as Windows reads it",
      g.get("linked") and g.get("version", 0) >= 7 and f"Version={g.get('version')}" in g.get("gpt", "")
      and "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" in g.get("ext", "") and g.get("entries") == 5,
      res.stderr[-300:] or g)

code, out = gpo("set", "ExampleSetting", "ExampleText=locked", "--control")
controls = gpo_request({"op": "show", "site": "lan", "control": True}, DC)["machine"]
LINKS = r"""
import sys
import ldb
sys.path.insert(0, "/fabric")
from open_samdb import open_samdb
samdb, lp = open_samdb("/data/etc/smb.conf")
for name in ("admin settings", "controls"):
    g = samdb.search(base="CN=Policies,CN=System," + str(samdb.domain_dn()), scope=ldb.SCOPE_ONELEVEL,
                     expression="(displayName=fabric: lan %s)" % name, attrs=["cn"])[0]
    link = str(samdb.search(base="OU=lan,OU=sites," + str(samdb.domain_dn()), scope=ldb.SCOPE_BASE,
                            attrs=["gPLink"])[0]["gPLink"][0]).lower()
    print(name, link.split(str(g.dn).lower() + ";")[1][0] if str(g.dn).lower() + ";" in link else "-")
"""
links = subprocess.run(["docker", "exec", "-i", DC, "python3", "-"], input=LINKS, capture_output=True, text=True).stdout
check("a policy set as a control goes to lan's controls GPO, linked enforced (2), the admin settings GPO not "
      "(0), and the admin settings keep their own value (2.1.6.20)",
      code == 0 and ["Software\\Policies\\Example\\Starter", "ExampleText", 1, "locked"] in controls
      and "admin settings 0" in links and "controls 2" in links
      and ["Software\\Policies\\Example\\Starter", "ExampleText", 1, "hello"] in machine(), (out, links, controls))
code, out = gpo("clear", "ExampleSetting", "--control")
check("clearing it as a control empties the controls GPO only",
      code == 0 and gpo_request({"op": "show", "site": "lan", "control": True}, DC)["machine"] == []
      and ["Software\\Policies\\Example\\Starter", "ExampleText", 1, "hello"] in machine(), out)

check("refused: an unknown policy", refused({"op": "set", "site": "lan", "policy": "NoSuchPolicy"}, "no policy"))
check("refused: an element the policy does not have",
      refused({"op": "set", "site": "lan", "policy": TEXT_POL, "values": {"nope": "x"}}, "has no element"))
check("refused: a boolean that is not on or off",
      refused({"op": "set", "site": "lan", "policy": BOOL_POL, "values": {BOOL_EL: "maybe"}}, "on or off"))
bad = os.path.join(W, "bad")
os.makedirs(bad, exist_ok=True)
with open(os.path.join(bad, "broken.admx"), "w") as f:
    f.write("<policyDefinitions><not closed")
code, out = gpo("load", bad)
check("refused: a file that is not a template, before anything is written",
      code == 1 and "broken" not in "".join(gpo_request({"op": "templates"}, DC)), out)
check("every change audited", {"GPO_TEMPLATES_LOAD", "GPO_SET", "GPO_CLEAR"} <= set(AUDIT), AUDIT)

subprocess.run(["docker", "rm", "-f", DC], capture_output=True)
subprocess.run(["docker", "network", "rm", NET], capture_output=True)
print(f"\n{FAILED and 'FAILED' or 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
