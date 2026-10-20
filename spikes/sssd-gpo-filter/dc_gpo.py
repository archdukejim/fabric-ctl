"""Spike helper, run inside the DC by spike.py (python3 - on stdin, ARGS prepended as JSON): makes and changes the
spike's GPOs with fabric's own ensure_gpo (as converge makes its GPOs), then sets their security filtering the way
GPMC does: Authenticated Users keep Read, only the filtering group gets Read + Apply Group Policy."""
import json
import os
import re
import sys

sys.path.insert(0, "/fabric")
import ldb  # noqa: E402
from samba.dcerpc import security  # noqa: E402
from samba.ndr import ndr_unpack  # noqa: E402
from samba.sd_utils import SDUtils  # noqa: E402

from acl_entries import sid_of  # noqa: E402
from ensure_gpo import ensure_gpo  # noqa: E402
from find_gpo import find_gpo  # noqa: E402
from open_samdb import open_samdb  # noqa: E402
from set_gpo_acl import set_gpo_acl  # noqa: E402

EXT = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"
INF = "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"
APPLY = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"      # the Apply Group Policy extended right
ADMINS = "S-1-5-32-544"

samdb, lp = open_samdb("/data/etc/smb.conf")
base = str(samdb.domain_dn())
domsid = security.dom_sid(samdb.get_domain_sid())


def inf(rights):
    """GptTmpl.inf as fabric's old logon_rights_policy wrote it: UTF-16LE with BOM, CRLF."""
    text = "[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n[Privilege Rights]\r\n"
    for right, names in rights.items():
        text += f"{right} = " + ",".join(f"*{sid_of(samdb, n)}" for n in names) + f",*{ADMINS}\r\n"
    return b"\xff\xfe" + text.encode("utf-16-le")


def sddl(dn):
    res = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["nTSecurityDescriptor"])
    return ndr_unpack(security.descriptor, res[0]["nTSecurityDescriptor"][0]).as_sddl(domsid)


def set_filter(dn, guid, group):
    """group None: the default (Authenticated Users apply it); else only `group` applies it."""
    old = sddl(dn)
    owner_group, dacl = old.split("D:", 1)
    sacl = ""
    if "S:" in dacl:
        dacl, sacl = dacl.split("S:", 1)
        sacl = "S:" + sacl
    flags = re.match(r"^[A-Z]*", dacl).group(0)
    aces = [a for a in re.findall(r"\([^)]*\)", dacl) if not a.rstrip(")").endswith(";AU")]
    aces.append("(A;CI;RPLCLORC;;;AU)")
    if group is None:
        aces.append(f"(OA;CI;CR;{APPLY};;AU)")
    else:
        gsid = sid_of(samdb, group)
        aces += [f"(A;CI;RPLCLORC;;;{gsid})", f"(OA;CI;CR;{APPLY};;{gsid})"]
    new = owner_group + "D:" + flags + "".join(aces) + sacl
    SDUtils(samdb).modify_sd_on_dn(dn, security.descriptor.from_sddl(new, domsid), controls=["sd_flags:1:4"])
    set_gpo_acl(samdb, lp, guid)
    return old, sddl(dn)


def set_aces(dn, guid, aces):
    """spike28: the GPO's own (non-inherited) entries for Authenticated Users and every Apply Group Policy entry
    replaced by `aces` (SDDL; "{name}" is that account's or group's SID, e.g. "{G1}", "{SD12$}")."""
    old = sddl(dn)
    owner_group, dacl = old.split("D:", 1)
    sacl = ""
    if "S:" in dacl:
        dacl, sacl = dacl.split("S:", 1)
        sacl = "S:" + sacl
    flags = re.match(r"^[A-Z]*", dacl).group(0)
    spike_sids = {sid_of(samdb, n) for n in ARGS.get("spike_names", [])}  # noqa: F821
    keep = [a for a in re.findall(r"\([^)]*\)", dacl)
            if not a.rstrip(")").endswith(";AU") and APPLY not in a.lower()
            and a.rstrip(")").rsplit(";", 1)[-1] not in spike_sids]
    new_aces = [re.sub(r"\{([^}]+)\}", lambda m: sid_of(samdb, m.group(1)), a) for a in aces]
    new = owner_group + "D:" + flags + "".join(keep + new_aces) + sacl
    SDUtils(samdb).modify_sd_on_dn(dn, security.descriptor.from_sddl(new, domsid), controls=["sd_flags:1:4"])
    set_gpo_acl(samdb, lp, guid)
    return old, sddl(dn)


def gplink(dn):
    return str(samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["gPLink"])[0].get("gPLink", [""])[0])


def set_gplink(dn, value):
    samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "gPLink": value}, ldb.FLAG_MOD_REPLACE))


def links(dn):
    return [p for p in gplink(dn).strip("[]").split("][") if p]


op = ARGS["op"]  # noqa: F821 (prepended by spike.py)
out = {}
if op == "gpo":
    link_dn = ARGS["link_dn"]
    out["done"] = ensure_gpo(samdb, lp, ARGS["name"], link_dn, EXT, {INF: inf(ARGS["rights"])})
    dn, guid, version = find_gpo(samdb, ARGS["name"])
    out["guid"], out["version"] = guid, version
    if "aces" in ARGS:
        out["sd_before"], out["sd_after"] = set_aces(dn, guid, ARGS["aces"])
    else:
        out["sd_before"], out["sd_after"] = set_filter(dn, guid, ARGS.get("filter"))
    out["gplink"] = gplink(link_dn)
elif op == "aces":              # spike28: change an existing GPO's filtering entries only
    dn, guid, _ = find_gpo(samdb, ARGS["name"])
    out["sd_before"], out["sd_after"] = set_aces(dn, guid, ARGS["aces"])
elif op == "sids":              # spike28: SIDs and primary groups of named accounts
    for n in ARGS["names"]:
        res = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, expression=f"(sAMAccountName={n})",
                           attrs=["primaryGroupID"])
        out[n] = {"sid": sid_of(samdb, n), "primaryGroupID": str(res[0].get("primaryGroupID", [""])[0])}
elif op == "unlink":
    dn, guid, _ = find_gpo(samdb, ARGS["name"])
    kept = [p for p in links(ARGS["link_dn"]) if not p.lower().startswith(f"ldap://{dn.lower()};")]
    set_gplink(ARGS["link_dn"], "".join(f"[{p}]" for p in kept))
    out["gplink"] = gplink(ARGS["link_dn"])
elif op == "order":             # the named GPOs' links put at the end of gPLink in the order given
    dns = [find_gpo(samdb, n)[0].lower() for n in ARGS["names"]]
    parts = links(ARGS["link_dn"])
    others = [p for p in parts if not any(p.lower().startswith(f"ldap://{d};") for d in dns)]
    mine = [next(p for p in parts if p.lower().startswith(f"ldap://{d};")) for d in dns]
    set_gplink(ARGS["link_dn"], "".join(f"[{p}]" for p in others + mine))
    out["gplink"] = gplink(ARGS["link_dn"])
elif op == "show":              # what is linked at an OU, and the privilege rights each GPO sets
    out["gplink"] = gplink(ARGS["link_dn"])
    out["gpos"] = []
    for part in links(ARGS["link_dn"]):
        dn = part.split(";")[0][len("LDAP://"):]
        res = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["displayName", "cn", "flags"])
        guid = str(res[0]["cn"][0])
        path = os.path.join(lp.get("path", "sysvol"), lp.get("realm").lower(), "Policies", guid, *INF.split("/"))
        rights = ""
        if os.path.exists(path):
            text = open(path, "rb").read().decode("utf-16")
            rights = [ln for ln in text.splitlines() if ln.startswith("Se")]
        out["gpos"].append({"name": str(res[0]["displayName"][0]), "guid": guid, "rights": rights})
    out["samba"] = os.popen("samba -V").read().strip()
print("RESULT " + json.dumps(out))
