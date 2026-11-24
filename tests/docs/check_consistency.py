#!/usr/bin/env python3
"""Cross-checks between the docs and the code — the facts a reader relies
on that drift silently otherwise:

  readmes      every folder has a README.md naming each of its files and subfolders
  vars         every setting in vars.yaml.j2 is in the manual's settings (SETTINGS), which names no setting that is gone
  cli          every `fabricctl` command and subcommand is in the docs
  api          fabric-agent's routes = the permission table = the list in the manual (1.3.3)
  permissions  every permission is explained in the manual (1.3.3, 1.6.8, 1.8)
  suites       every test suite in tests/run-all.sh has a folder or file and is in tests/README.md
  steps        every setup step is in the manual's installation chapters (3.2, 3.3)
  links        every relative Markdown link points at something that exists

    python3 tests/docs/check_consistency.py [check ...]     exit 1 if any check finds a problem
"""
import ast
import os
import re
import sys

# the shared helpers live with the generator in scripts/docs/
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "scripts", "docs"))  # noqa: E501
from product_code import REPO, tracked_files  # noqa: E402

SKIP_README = {"__init__.py", "README.md"}     # a README need not list itself or package markers


# the settings reference: how settings work (1.1.8), then each part's settings
SETTINGS = ("1.1.8", "1.1.9", "1.2.10", "1.3.7", "1.2.11", "1.2.12", "1.4.2", "1.5.2", "1.6.9", "1.6.10", "1.8.4")
WHERE = "the manual's settings (1.1.8 and each part's)"


def _read(path):
    return open(os.path.join(REPO, path), encoding="utf-8").read()


def _manual(*numbers):
    """Purpose: the text of the manual's subchapters under the given chapter or subchapter numbers.
    Inputs:  numbers — "1.1.8", "1.3.3", … (a subchapter file is docs/volume_*/<V.C.S>-name.md).
    Returns: their text, joined, in number order; "" when none match.
    Fails:   OSError if a matching file cannot be read.
    Feeds:   check_vars, check_api, check_permissions, check_steps."""
    def key(p):
        return [int(x) for x in os.path.basename(p).split("-")[0].split(".")]
    files = [p for p in tracked_files("docs") if re.match(r"docs/volume_\d_[a-z_]+/\d+(\.\d+)+-", p)
             and any(os.path.basename(p).split("-")[0] == n or os.path.basename(p).startswith(n + ".")
                     for n in numbers)]
    return "\n".join(_read(p) for p in sorted(files, key=key))


def check_readmes():
    """Purpose: each folder's README.md names every file and subfolder in it.
    Inputs:  none (the repository's files; hidden folders, the repository
             root is exempt).
    Returns: problems (str), one per missing README or unlisted entry.
    Fails:   never (unreadable READMEs count as missing).
    Feeds:   main."""
    folders = {}
    for p in tracked_files():
        parts = p.split("/")
        if len(parts) < 2 or any(x.startswith(".") for x in parts[:-1]):
            continue
        folder = "/".join(parts[:-1])
        folders.setdefault(folder, set()).add(parts[-1])
        for i in range(1, len(parts) - 1):                    # the subfolder, in its parent's README
            folders.setdefault("/".join(parts[:i]), set()).add(parts[i] + "/")
    out = []
    for folder, entries in sorted(folders.items()):
        readme = os.path.join(REPO, folder, "README.md")
        if not os.path.exists(readme):
            out.append(f"{folder}/: no README.md")
            continue
        text = open(readme, encoding="utf-8").read()
        for name in sorted(entries - SKIP_README):
            bare = name.rstrip("/")
            if not re.search(r"[`\[(/ ]" + re.escape(bare) + r"(/|`|\]|\)|\b)", text):
                out.append(f"{folder}/README.md does not mention {name}")
    return out


def _vars_template_keys():
    keys = set()
    for line in _read("templates/vars.yaml.j2").splitlines():
        m = re.match(r"^([a-z][a-z0-9_]*):", line)
        if m:
            keys.add(m.group(1))
    return keys


def check_vars():
    """Purpose: vars.yaml.j2 and the manual's settings (SETTINGS) name the same settings.
    Inputs:  none.
    Returns: problems: settings without docs, and documented settings
             (`x` headings, first table cells) that do not exist.
    Fails:   OSError if a file is unreadable.
    Feeds:   main."""
    keys = _vars_template_keys()
    doc = _manual(*SETTINGS)
    documented = set(re.findall(r"^###+\s+(?:\d+(?:\.\d+)+\s+)?`([a-z][a-z0-9_]*)`", doc, re.M))
    documented |= set(re.findall(r"^\|\s*`([a-z][a-z0-9_]*)`\s*\|", doc, re.M))
    # a setting read only where it is used (`x | default(...)` in a template, v.get("x") in code) is real too
    code = "\n".join(_read(p) for p in tracked_files("src", "templates")
                     if p.endswith((".j2", ".py", ".sh")) and not p.endswith("vars.yaml.j2"))
    used = {k for k in documented - keys
            if re.search(rf"(\{{\{{-?\s*{k}\b|\b{k}\s*\||get\(\s*['\"]{k}['\"]|\[['\"]{k}['\"]\])", code)}
    out = [f"vars.yaml.j2 setting `{k}` is not in {WHERE}" for k in sorted(keys) if f"`{k}`" not in doc]
    out += [f"{WHERE} documents `{k}`, which nothing reads" for k in sorted(documented - keys - used)]
    return out


def _cli_commands():
    """(command, subcommand or None) pairs from cli.py's docstring and every
    `fabricctl <cmd> <sub>` in a USAGE string."""
    cmds = set()
    doc = ast.get_docstring(ast.parse(_read("src/fabriclib/cli.py"))) or ""
    for m in re.finditer(r"^\s+fabricctl ([a-z][a-z-]*)(?: ([a-z|-]+))?", doc, re.M):
        subs = [s for s in (m.group(2) or "").split("|") if s and not s.startswith("-")]
        cmds.add((m.group(1), None))
        cmds.update((m.group(1), s) for s in subs)
    for path in tracked_files("src/fabriclib"):
        if path.endswith(".py"):
            for usage in re.findall(r'USAGE = """(.*?)"""', _read(path), re.S):
                for m in re.finditer(r"fabricctl ([a-z][a-z-]*) ([a-z][a-z-]*)", usage):
                    cmds.add((m.group(1), m.group(2)))
    return cmds


def check_cli():
    """Purpose: every fabricctl command and subcommand appears in the docs.
    Inputs:  none (cli.py, the USAGE strings; the manual, README.md).
    Returns: problems, one per command not mentioned as `fabricctl <cmd> [<sub>]`.
    Fails:   OSError if cli.py is missing.
    Feeds:   main."""
    docs = "\n".join(_read(p) for p in tracked_files("docs", "README.md") if p.endswith(".md"))
    out = []
    for cmd, sub in sorted(_cli_commands(), key=lambda c: (c[0], c[1] or "")):
        pattern = rf"fabricctl {re.escape(cmd)}" + (rf"(?: [^\n`]*?)?[ |]{re.escape(sub)}\b" if sub else r"\b")
        if not re.search(pattern, docs):
            out.append(f"`fabricctl {cmd}{' ' + sub if sub else ''}` is not in the docs")
    return out


def _routes_in_table():
    src = ast.parse(_read("src/fabriclib/rbac/required_permission.py"))
    routes = set()
    for node in src.body:
        if isinstance(node, ast.Assign) and node.targets[0].id in ("GET", "POST"):
            for key in ast.literal_eval(node.value):
                routes.add((node.targets[0].id, "/".join(key)))
    return routes


def check_api():
    """Purpose: fabric-agent's permission table and the manual (1.3.3) list the same routes.
    Inputs:  none.
    Returns: problems: routes the table has but the docs do not, and routes
             the docs list that the table does not (so they would be refused).
    Fails:   OSError if a file is missing.
    Feeds:   main."""
    table = {r for _, r in _routes_in_table()}
    doc = _manual("1.3.3")
    listed = set()
    for m in re.finditer(r"`(/v1/[^`]+)`", doc):
        path = m.group(1)[len("/v1/"):]
        brace = re.match(r"(.*)\{([^}]*)\}(.*)", path)                     # /v1/x/{a,b} -> x/a, x/b
        variants = [brace.group(1) + v + brace.group(3) for v in brace.group(2).split(",")] if brace else [path]
        for v in variants:
            listed.add(re.sub(r"<[^>]+>", "*", v))
    out = [f"agent route /v1/{r} is not in the manual (1.3.3)" for r in sorted(table - listed)]
    out += [f"the manual (1.3.3) lists /v1/{r}, which fabric-agent refuses (not in the permission table)"
            for r in sorted(listed - table)]
    return out


def check_permissions():
    """Purpose: every permission in rbac/permissions.py is explained in the manual (1.3.3, 1.6.8, 1.8).
    Inputs:  none.
    Returns: problems, one per permission not mentioned as `area:action`.
    Fails:   OSError / SyntaxError if permissions.py is unreadable.
    Feeds:   main."""
    src = ast.parse(_read("src/fabriclib/rbac/permissions.py"))
    perms = next(ast.literal_eval(n.value) for n in src.body
                 if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "PERMISSIONS")
    doc = _manual("1.3.3", "1.6.8", "1.8")
    return [f"permission `{p}` is not in the manual (1.3.3, 1.6.8, 1.8)" for p in sorted(perms) if f"`{p}`" not in doc]


def check_suites():
    """Purpose: every suite run-all.sh knows exists and is described in tests/README.md.
    Inputs:  none.
    Returns: problems: suites with no tests/<suite> folder or script, or not in tests/README.md.
    Fails:   OSError if run-all.sh is missing.
    Feeds:   main."""
    suites = re.findall(r"^\s+([a-z0-9]+)\)\s+run ", _read("tests/run-all.sh"), re.M)
    readme = _read("tests/README.md") if os.path.exists(os.path.join(REPO, "tests/README.md")) else ""
    out = []
    for s in suites:
        if not any(os.path.exists(os.path.join(REPO, "tests", c)) for c in (s, f"{s}.py", f"{s}_test.py", f"{s}_check.sh")):
            out.append(f"suite {s}: no tests/{s} folder or script")
        if f"`{s}`" not in readme:
            out.append(f"suite {s} is not in tests/README.md")
    return out


def check_steps():
    """Purpose: every setup step (setup/steps.py) is described in the manual's installation chapters (3.2, 3.3).
    Inputs:  none.
    Returns: problems, one per step name not mentioned as `name`.
    Fails:   OSError if a file is missing.
    Feeds:   main."""
    steps = re.findall(r'^\s+\("([a-z]+)", ', _read("src/fabriclib/setup/steps.py"), re.M)
    doc = _manual("3.2", "3.3", "3.5.1")
    return [f"setup step `{s}` is not in the manual (3.2, 3.3)" for s in steps if f"`{s}`" not in doc]


def _anchors(path):
    """Purpose: the heading anchors of a Markdown file, as GitHub (and the in-browser manual) make them.
    Inputs:  path — repository-relative .md file.
    Returns: set of anchors (lower case, punctuation other than "-" dropped, spaces as "-"); "#" lines inside code
             fences are not headings.
    Fails:   OSError if the file cannot be read.
    Feeds:   check_links."""
    out, fence = set(), False
    for line in _read(path).split("\n"):
        if line.lstrip().startswith("```"):
            fence = not fence
        elif not fence and line.startswith("#"):
            text = line.lstrip("#").strip().lower()
            out.add(re.sub(r"[^\w\- ]", "", text).replace(" ", "-"))
    return out


def check_links():
    """Purpose: relative links in Markdown files resolve: the file exists and, for a .md target, the #anchor is one
             of its headings; a link target with whitespace in it is broken too.
    Inputs:  none (every tracked .md; http(s) and mailto links are skipped).
    Returns: problems, one per broken link (file and target).
    Fails:   never.
    Feeds:   main."""
    out = []
    for path in tracked_files():
        if not path.endswith(".md"):
            continue
        text = _read(path)
        for target in re.findall(r"\]\(([^)\s]+\s[^)]*)\)", text):
            if not re.match(r"(https?:|mailto:)", target) and "\n" not in target and not target.startswith("<"):
                out.append(f"{path}: link with a space in its target: {target}")
        for target in re.findall(r"\]\(([^)\s]+)\)", text):
            if re.match(r"(https?:|mailto:)", target):
                continue
            rel, _, frag = target.partition("#")
            dest = os.path.normpath(os.path.join(os.path.dirname(path), rel)).replace("\\", "/") if rel else path
            if not os.path.exists(os.path.join(REPO, dest)):
                out.append(f"{path}: broken link {target}")
            elif frag and dest.endswith(".md") and frag not in _anchors(dest):
                out.append(f"{path}: no heading for #{frag} in {dest}")
    return out


CHECKS = {"readmes": check_readmes, "vars": check_vars, "cli": check_cli, "api": check_api,
          "permissions": check_permissions, "suites": check_suites, "steps": check_steps, "links": check_links}


def main(argv):
    """Purpose: run the checks and report.
    Inputs:  argv — names of checks to run (none: all).
    Returns: exit status: 0 all clean, 1 any problem, 2 unknown check name.
    Fails:   as the individual checks.
    Feeds:   tests/docs/run.py."""
    names = argv or list(CHECKS)
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        print("unknown check: " + ", ".join(unknown))
        return 2
    bad = 0
    for name in names:
        problems = CHECKS[name]()
        bad += len(problems)
        for p in problems:
            print(f"[{name}] {p}")
        print(f"{'FAIL' if problems else 'PASS'} {name}: {len(problems)} problem(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
