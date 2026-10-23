#!/usr/bin/env python3
"""The entry-point inventory (decision 2.1.1.38, manual 3.1.2.5): every way a person or a client puts something into
fabric, generated from where each kind is declared, into tests/entrypoints.yaml.

    python3 scripts/docs/entrypoints.py            write tests/entrypoints.yaml
    python3 scripts/docs/entrypoints.py --check    exit 1 if the committed inventory is not what the code declares
    python3 scripts/docs/entrypoints.py --gaps     print every missing case ("<id> +" or "<id> -"), for
                                                   tests/entrypoints-gaps.txt (the ratchet, 2.1.1.46)

IDs: cli:<command>[.<sub>], ask:<area>.<name>, agent:<get|post>.<segments>, web:<get|post>.<path segments>,
setting:<key>; a placeholder in a path is `*`.
"""
import ast
import os
import re
import sys

from product_code import REPO

INVENTORY = "tests/entrypoints.yaml"
GAPS = "tests/entrypoints-gaps.txt"
REASONS = "tests/entrypoints-reasons.yaml"
SRC = os.path.join(REPO, "src")
MARKER = re.compile(r"#\s*covers:\s*(.+?)\s*$")
CASE = re.compile(r"^([a-z]+:[^\s]+)\s+([+-]+)$")


def _walk(top):
    """Purpose: os.walk in a fixed order (sorted folders and files), so the inventory is the same on every machine: an
             ID declared in several files is recorded with the last in that order.
    Inputs:  top — the folder to walk.
    Returns: os.walk's (folder, dirs, files) triples, sorted.
    Fails:   never (as os.walk).
    Feeds:   _cli, _ask, markers."""
    for folder, dirs, files in os.walk(top):
        dirs.sort()
        yield folder, dirs, sorted(files)


def _read(path):
    """Purpose: a repository file's text.
    Inputs:  path — repository-relative, `/`-separated.
    Returns: its content (UTF-8).
    Fails:   OSError if it cannot be read.
    Feeds:   every collector."""
    with open(os.path.join(REPO, *path.split("/")), encoding="utf-8") as f:
        return f.read()


def _cli():
    """Purpose: fabricctl's commands: the top level (fabriclib/cli.py: `cmd == "x"`, `cmd in (...)`, the flag forms of
             `_flags`) and each command's subcommands (the `fabricctl <command> <sub>` lines of every
             run_*_command.py's USAGE).
    Inputs:  none (reads src/).
    Returns: {id: source}.
    Fails:   OSError on an unreadable file.
    Feeds:   collect."""
    found = {}
    cli = _read("src/fabriclib/cli.py")
    for m in re.finditer(r'cmd == "([a-z][a-z0-9-]*)"', cli):
        found[f"cli:{m.group(1)}"] = "src/fabriclib/cli.py"
    for m in re.finditer(r"cmd in \(([^)]*)\)", cli):
        for name in re.findall(r'"([a-z][a-z0-9-]*)"', m.group(1)):
            if name != "help":
                found[f"cli:{name}"] = "src/fabriclib/cli.py"
    flags = re.search(r"def _flags\(.*?(?=\ndef |\Z)", cli, re.S)
    for name in re.findall(r'"--([a-z][a-z0-9-]*)"', flags.group(0) if flags else ""):
        found[f"cli:--{name}"] = "src/fabriclib/cli.py (_flags)"
    for folder, _dirs, files in _walk(os.path.join(SRC, "fabriclib")):
        for name in files:
            if not (name.startswith("run_") and name.endswith("_command.py")):
                continue
            path = os.path.relpath(os.path.join(folder, name), REPO).replace(os.sep, "/")
            tree = ast.parse(_read(path))
            usage = next((n.value.value for n in tree.body if isinstance(n, ast.Assign)
                          and any(getattr(t, "id", "") == "USAGE" for t in n.targets)
                          and isinstance(n.value, ast.Constant)), "")
            for m in re.finditer(r"fabricctl ([a-z][a-z0-9-]*) ([a-z][a-z0-9-]*)", usage):
                found[f"cli:{m.group(1)}.{m.group(2)}"] = path
    return found


def _ask():
    """Purpose: the questions: every ask()/ask_secret() call's ID in src/ (manual 1.1.5.6); an ID built from a
             variable (an f-string) has `*` for the variable part.
    Inputs:  none (reads src/).
    Returns: {id: source}.
    Fails:   OSError on an unreadable file.
    Feeds:   collect."""
    found = {}
    for folder, _dirs, files in _walk(SRC):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.relpath(os.path.join(folder, name), REPO).replace(os.sep, "/")
            for node in ast.walk(ast.parse(_read(path))):
                if not (isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", ""))
                        in ("ask", "ask_secret", "ask_yes_no") and node.args):
                    continue
                qid = node.args[0]
                if isinstance(qid, ast.Constant) and isinstance(qid.value, str):
                    found[f"ask:{qid.value}"] = path
                elif isinstance(qid, ast.JoinedStr):
                    found["ask:" + "".join(p.value if isinstance(p, ast.Constant) else "*" for p in qid.values)] = path
    return found


def _agent():
    """Purpose: fabric-agent's routes: the permission table, the routes' one list (a route not in it is refused).
    Inputs:  none (imports fabriclib.rbac.required_permission).
    Returns: {id: source}.
    Fails:   ImportError if the table cannot be imported.
    Feeds:   collect."""
    sys.path.insert(0, SRC)
    from fabriclib.rbac.required_permission import GET, POST
    source = "src/fabriclib/rbac/required_permission.py"
    return {f"agent:{verb}.{'.'.join(route)}": source for verb, table in (("get", GET), ("post", POST))
            for route in table}


def _web():
    """Purpose: the web console's pages (webui/routes/get_page.py: `path == "/x"`, and `_rest(path, "/x/")` for a
             page per name, /x/*) and forms (`action` in templates/webui-app/; a Jinja placeholder is `*`, a form
             with method get is its page).
    Inputs:  none (reads src/webui and templates/webui-app).
    Returns: {id: source}.
    Fails:   OSError on an unreadable file.
    Feeds:   collect."""
    def ident(verb, path):
        parts = [("*" if "{{" in p else p) for p in path.strip("/").split("/") if p]
        return f"web:{verb}." + (".".join(parts) or "home")

    found = {}
    for m in re.finditer(r'path == "(/[^"]*)"', _read("src/webui/routes/get_page.py")):
        found[ident("get", m.group(1))] = "src/webui/routes/get_page.py"
    for m in re.finditer(r'_rest\(path, "(/[^"]*/)"\)', _read("src/webui/routes/get_page.py")):
        found[ident("get", m.group(1) + "{{ name }}")] = "src/webui/routes/get_page.py"
    folder = os.path.join(REPO, "templates", "webui-app")
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".html"):
            continue
        for m in re.finditer(r"<form\b([^>]*)>", _read(f"templates/webui-app/{name}")):
            attrs = m.group(1)
            action = re.search(r'action="([^"]+)"', attrs)
            if not action:
                continue
            verb = "get" if re.search(r'method="get"', attrs, re.I) else "post"
            found[ident(verb, action.group(1))] = f"templates/webui-app/{name}"
    return found


def _settings():
    """Purpose: the settings: the top-level keys of the settings file's template.
    Inputs:  none (reads templates/vars.yaml.j2).
    Returns: {id: source}.
    Fails:   OSError if it cannot be read.
    Feeds:   collect."""
    return {f"setting:{k}": "templates/vars.yaml.j2"
            for k in re.findall(r"^([a-z][a-z0-9_]*):", _read("templates/vars.yaml.j2"), re.M)}


def collect():
    """Purpose: the whole inventory.
    Inputs:  none.
    Returns: {id: source}, every kind.
    Fails:   as the collectors.
    Feeds:   render, gaps; tests/docs/check_entrypoints.py."""
    found = {}
    for part in (_cli, _ask, _agent, _web, _settings):
        found.update(part())
    return found


def render(found):
    """Purpose: the inventory file's text, stable (sorted) so a change shows in review.
    Inputs:  found — {id: source}.
    Returns: YAML text.
    Fails:   never.
    Feeds:   main."""
    lines = ["# Generated by scripts/docs/entrypoints.py (manual 3.1.2.5): do not edit.",
             "# id: where it is declared"]
    lines += [f'"{k}": "{found[k]}"' for k in sorted(found)]
    return "\n".join(lines) + "\n"


def markers():
    """Purpose: every coverage marker in tests/: `# covers: <id> [<id> ...] +|-` (both signs: `+-`).
    Inputs:  none (reads tests/).
    Returns: {id: set of signs}, and [(file:line, id)] for every marker naming something (for the check).
    Fails:   never (unreadable files are skipped).
    Feeds:   gaps; tests/docs/check_entrypoints.py."""
    covered, named = {}, []
    tests = os.path.join(REPO, "tests")
    for folder, _dirs, files in _walk(tests):
        for name in files:
            if not name.endswith((".py", ".sh")):
                continue
            path = os.path.join(folder, name)
            try:
                with open(path, encoding="utf-8") as f:
                    text = f.read().splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            rel = os.path.relpath(path, REPO).replace(os.sep, "/")
            for n, line in enumerate(text, 1):
                m = MARKER.search(line)
                if not m:
                    continue
                words = m.group(1).split()
                signs = words[-1] if words and set(words[-1]) <= {"+", "-"} else ""
                for ident in (words[:-1] if signs else words):
                    covered.setdefault(ident, set()).update(signs)
                    named.append((f"{rel}:{n}", ident))
    return covered, named


def reasons():
    """Purpose: the settings that need no negative case, with why (tests/entrypoints-reasons.yaml: `<id>: reason`).
    Inputs:  none.
    Returns: {id: reason} (empty when the file does not exist).
    Fails:   never.
    Feeds:   gaps."""
    try:
        text = _read(REASONS)
    except OSError:
        return {}
    return {m.group(1): m.group(2).strip() for m in re.finditer(r'^"?([a-z]+:[^":\s]+)"?:\s*(.+)$', text, re.M)}


def gaps(found=None):
    """Purpose: every missing case: an entry point without a positive (`+`) or a negative (`-`) marker, the latter
             unless a reason says it cannot be wrong.
    Inputs:  found — the inventory (collected when None).
    Returns: sorted ["<id> +", "<id> -", ...].
    Fails:   as collect.
    Feeds:   main (--gaps); tests/docs/check_entrypoints.py."""
    found = collect() if found is None else found
    covered, _named = markers()
    excused = reasons()
    missing = []
    for ident in sorted(found):
        signs = covered.get(ident, set())
        if "+" not in signs:
            missing.append(f"{ident} +")
        if "-" not in signs and ident not in excused:
            missing.append(f"{ident} -")
    return missing


def main(argv):
    """Purpose: write, check or print gaps (module docstring).
    Inputs:  argv — the arguments.
    Returns: exit status: 0, or 1 when --check finds the inventory stale.
    Fails:   as collect.
    Feeds:   tests/docs/check_entrypoints.py (--check through it), the owner and agents."""
    found = collect()
    text = render(found)
    path = os.path.join(REPO, *INVENTORY.split("/"))
    if argv[:1] == ["--gaps"]:
        print("\n".join(gaps(found)))
        return 0
    if argv[:1] == ["--check"]:
        try:
            with open(path, encoding="utf-8") as f:
                current = f.read()
        except OSError:
            current = ""
        if current != text:
            print(f"{INVENTORY} is not what the code declares: run python3 scripts/docs/entrypoints.py")
            return 1
        print(f"{INVENTORY}: {len(found)} entry points, current")
        return 0
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"{INVENTORY}: {len(found)} entry points")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
