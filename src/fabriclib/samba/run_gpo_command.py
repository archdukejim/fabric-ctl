import base64
import getpass
import os
import shutil

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.deploy.deploy_paths import deploy_paths
from fabriclib.samba.clear_gpo_policy import clear_gpo_policy
from fabriclib.samba.gpo_request import gpo_request
from fabriclib.samba.set_gpo_policy import set_gpo_policy

USAGE = """usage: fabricctl gpo load <folder>                 templates (.admx, <lang>/.adml) into the central store
       fabricctl gpo templates                     the templates in the central store
       fabricctl gpo list [<text>]                 policies whose name or title contains <text>, with their elements
       fabricctl gpo show [--control]              what this site's admin settings (or controls) GPO sets
       fabricctl gpo set <policy> [<element>=<value> …] [--disabled] [--control]
       fabricctl gpo clear <policy> [--control]    back to "not configured"
       fabricctl gpo starter <folder>              copy fabric's blank starter template (.admx and en-US/.adml) there
  Policies apply to this site's machines (or people, for user policies) through its "fabric: <site> admin settings"
  GPO, which the sites below may override; with --control through its "fabric: <site> controls" GPO, linked
  enforced, which they may not. Values: a number, text, on/off, an option's name or number, or a list as a;b;c
  (manual 4.6.8)."""


def _files(folder):
    """Purpose: a folder's templates for the central store: *.admx, and <lang>/*.adml beside them.
    Inputs:  folder — str.
    Returns: {"<name>.admx" or "<lang>/<name>.adml": base64 text}.
    Fails:   ValidationError when the folder holds no .admx; OSError reading it.
    Feeds:   run_gpo_command (load)."""
    out = {}
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if name.lower().endswith(".admx") and os.path.isfile(path):
            out[name] = path
        elif os.path.isdir(path):
            for sub in sorted(os.listdir(path)):
                if sub.lower().endswith(".adml"):
                    out[f"{name}/{sub}"] = os.path.join(path, sub)
    if not any(n.lower().endswith(".admx") for n in out):
        raise ValidationError(f"no .admx template in {folder}")
    return {n: base64.b64encode(open(p, "rb").read()).decode() for n, p in out.items()}


def run_gpo_command(v, args, container="samba"):
    """Purpose: `fabricctl gpo …` (manual 4.6.8): only routes to the DC's editor (gpo_request) and prints.
    Inputs:  v — rendered vars (site_name); args — list of str after `gpo`; container — the DC's container.
    Returns: exit status: 0 ok, 1 refused, 2 usage.
    Fails:   OSError reading a folder or writing the audit log (propagates).
    Feeds:   cli.main."""
    if not args or args[0] not in ("load", "templates", "list", "show", "set", "clear", "starter"):
        print(USAGE)
        return 2
    op, rest, site = args[0], args[1:], v["site_name"]
    control = "--control" in rest
    rest = [a for a in rest if a != "--control"]
    try:
        if op == "starter":
            if len(rest) != 1:
                print(USAGE)
                return 2
            src = os.path.join(deploy_paths()["jinja"], "samba", "admx")
            shutil.copytree(src, rest[0], dirs_exist_ok=True)
            print(f"starter template copied to {rest[0]}: fill it in, then: sudo fabricctl gpo load {rest[0]}")
            return 0
        if op == "load":
            if len(rest) != 1:
                print(USAGE)
                return 2
            done = gpo_request({"op": "load", "site": site, "files": _files(rest[0])}, container, v)
            write_audit(getpass.getuser(), "GPO_TEMPLATES_LOAD", "files=" + ",".join(done), "cli")
            print("loaded: " + ", ".join(done))
        elif op == "templates":
            print("\n".join(gpo_request({"op": "templates"}, container)) or "no templates in the central store")
        elif op == "list":
            for p in gpo_request({"op": "policies", "match": " ".join(rest)}, container):
                print(f"{p['name']}  [{p['class']}, {p['template']}]  {p['display']}")
                if p["elements"]:
                    print("    " + "  ".join(p["elements"]))
        elif op == "show":
            s = gpo_request({"op": "show", "site": site, "control": control}, container)
            for scope in ("machine", "user"):
                for key, name, _, data in s[scope]:
                    print(f"{scope}: {key}\\{name} = {data}")
            if not s["machine"] and not s["user"]:
                print(f"fabric: {site} {'controls' if control else 'admin settings'} sets nothing")
        else:
            if not rest:
                print(USAGE)
                return 2
            values, enabled = {}, "--disabled" not in rest
            for item in (a for a in rest[1:] if a != "--disabled"):
                if "=" not in item:
                    raise ValidationError(f"{item}: give <element>=<value>")
                key, value = item.split("=", 1)
                values[key] = value
            if op == "set":
                done = set_gpo_policy(v, getpass.getuser(), rest[0], values, enabled, container=container,
                                      control=control)
            else:
                done = clear_gpo_policy(v, getpass.getuser(), rest[0], container=container, control=control)
            print("; ".join(done) or "already so")
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    return 0
